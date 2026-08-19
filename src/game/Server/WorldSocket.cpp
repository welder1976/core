/*
 * Copyright (C) 2005-2011 MaNGOS <http://getmangos.com/>
 * Copyright (C) 2009-2011 MaNGOSZero <https://github.com/mangos/zero>
 * Copyright (C) 2011-2016 Nostalrius <https://nostalrius.org>
 * Copyright (C) 2016-2017 Elysium Project <https://github.com/elysium-project>
 * Copyright (C) 2017-2024 VMaNGOS Project <https://github.com/vmangos>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include "WorldSocket.h"
#include "WorldSocketMgr.h"
#include "WorldSession.h"

#include "Auth/AuthCrypt.h"
#include "World.h"
#include "AccountMgr.h"
#include "SharedDefines.h"
#include "AddonHandler.h"
#include "Opcodes.h"
#include "Packet.h"
#include "ClientDefines.h"
#include "Packets/Query.h"
#include "Crypto/Hash/SHA1.h"
#include "Database/SqlPreparedStatement.h"
#include "Database/DatabaseEnv.h"
#include "DBCStores.h"
#include "Config/Config.h"
#include "Util.h"
#include "Errors.h"
#include "Utilities/Random.h"
#include "ObjectMgr.h"
#include "ObjectGuid.h"
#include "Player.h"

#include "IO/Networking/DNS.h"
#include "IO/Timer/AsyncSystemTimer.h"

#include <memory>
#include <cstdio>
#include <cstring>
#include <string>

namespace
{
std::string AzrtPacketBodyHex(WorldPacket const& packet, size_t maxBytes = 256)
{
    size_t const n = std::min(packet.size(), maxBytes);
    std::string hex;
    hex.reserve(n * 3 + 8);
    for (size_t i = 0; i < n; ++i)
    {
        char b[4];
        std::snprintf(b, sizeof(b), "%02X ", packet[i]);
        hex += b;
    }
    if (packet.size() > maxBytes)
        hex += "...";
    return hex;
}

// Emberveil opcode N is only a classic CMSG when the name is CMSG_* and the
// slot actually has a client handler. MSG_* are movement and must not be
// queued with Emberveil bodies (would apply garbage position).
bool AzrtCanPassthroughClassicCmsg(uint16 opcode, size_t size)
{
    if (opcode >= NUM_MSG_TYPES)
        return false;
    OpcodeHandler const& h = LookupOpcodeHandler(opcode);
    if (!h.impl.has_value() || !h.name)
        return false;
    if (std::strncmp(h.name, "CMSG_", 5) != 0)
        return false;
    switch (opcode)
    {
        case CMSG_CHAR_CREATE:
        case CMSG_CHAR_ENUM:
        case CMSG_CHAR_DELETE:
        case CMSG_CHAR_RENAME:
        case CMSG_PLAYER_LOGIN:
        case CMSG_AUTH_SESSION:
        case CMSG_WORLD_TELEPORT:
        case CMSG_CREATURE_QUERY: // Emberveil 0x60 is CHAR_ENUM
        case CMSG_PING:
        case CMSG_CANCEL_CAST:
        case CMSG_CAST_SPELL:
        case CMSG_AUCTION_SELL_ITEM: // Emberveil 0x256 is interact, not auction
        case CMSG_AUCTION_LIST_BIDDER_ITEMS: // Emberveil 0x264 is quest query
            return false;
        default:
            break;
    }
    return size == 0 || size == 1 || size == 4 || size == 8;
}

// Right-click / use: creature -> gossip, GO -> use. Not inspect/auction.
bool AzrtRemapGuidInteract(WorldPacket& packet, uint16 origOp)
{
    if (packet.size() != 8)
        return false;
    ObjectGuid guid;
    packet.rpos(0);
    packet >> guid;
    uint16 mapped = 0;
    if (guid.IsCreatureOrPet())
        mapped = CMSG_GOSSIP_HELLO;
    else if (guid.IsGameObject() || guid.IsMOTransport() || guid.IsTransport())
        mapped = CMSG_GAMEOBJ_USE;
    else
    {
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT 0x%X guid-interact drop %s",
                 uint32(origOp), guid.GetString().c_str());
        return false;
    }
    packet.Initialize(mapped, 8);
    packet << guid;
    packet.rpos(0);
    sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
             "WorldSocket: AZRT 0x%X -> %s %s",
             uint32(origOp), LookupOpcodeName(mapped), guid.GetString().c_str());
    return true;
}

// Emberveil in-world CMSG remaps. Returns false to drop the packet.
// Wire numbers collide with classic SMSG/CMSG ids — never queue an unmapped AZRT opcode.
bool AzrtRemapInWorldCmsg(WorldPacket& packet, WorldSession* session)
{
    uint16 const opcode = packet.GetOpcode();
    size_t const size = packet.size();

    // Official after SET_ACTIVE_MOVER / 0x200: empty notify CMSG (no dedicated SMSG).
    // Next server packets are VALUES 0x1FC + 0x172 — not CHAR_ENUM / CHAR_CREATE.
    if (size == 0 && (opcode == 0x42B || opcode == 0x416 || opcode == 0x4C2 ||
                      opcode == 0x92 || opcode == 0x500))
    {
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT post-enter CMSG 0x%X size=0 (consumed)",
                 uint32(opcode));
        return false;
    }
    if (opcode == 0x2 && size == 8)
    {
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT post-enter CMSG 0x2 size=8 (consumed)");
        return false;
    }

    // Official TXT: 0x4FB ↔ SMSG 0x3CC (guid + u32). Never answer with 0x509.
    if (opcode == 0x4FB && size == 8)
    {
        ObjectGuid guid;
        packet >> guid;
        if (session)
            session->AzrtSendQueryName(guid);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT 0x4FB -> SMSG 0x3CC guid=%s",
                 guid.GetString().c_str());
        return false; // consumed
    }

    // Official Frida 1:1 counts: 0x143↔0x04F(GO), 0x0DE↔0x509(creature), 0x05D↔0x294(item).
    // Do not pick type by entry DB lookup — collisions remap the wrong query.
    if ((opcode == 0x5D || opcode == 0x143 || opcode == 0xDE) && size >= 4)
    {
        uint32 entry = 0;
        memcpy(&entry, packet.contents(), sizeof(entry));
        uint16 mapped = CMSG_ITEM_QUERY_SINGLE;
        if (opcode == 0x143)
            mapped = CMSG_GAMEOBJECT_QUERY;
        else if (opcode == 0xDE)
            mapped = CMSG_CREATURE_QUERY;
        else
            mapped = CMSG_ITEM_QUERY_SINGLE; // 0x5D
        packet.SetOpcode(mapped);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
                 "WorldSocket: AZRT 0x%X -> %s entry=%u",
                 uint32(opcode), LookupOpcodeName(mapped), entry);
        return true;
    }

    // Same writer as 0x159 (1411a0ee0, raw 8-byte guid).
    if (opcode == 0x11 && size == 8)
    {
        packet.SetOpcode(CMSG_SET_ACTIVE_MOVER);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT 0x11 -> CMSG_SET_ACTIVE_MOVER");
        return true;
    }

    if (opcode == 0x159 && size == 8)
    {
        packet.SetOpcode(CMSG_SET_SELECTION);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT 0x159 -> CMSG_SET_SELECTION");
        return true;
    }

    // 0x47E @ 0x14496ABB0: stores/clears current target at +0x8f8, then
    // GAMEHIGHLIGHT*UNIT. Same 8-byte guid writer as 0x159. Must run before
    // the generic >=NUM_MSG_TYPES guid-click remap (would become gossip).
    if (opcode == 0x47E && size == 8)
    {
        packet.SetOpcode(CMSG_SET_SELECTION);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT 0x47E -> CMSG_SET_SELECTION");
        return true;
    }

    // 0x256 @ 0x1449693E0: right-click/use when object type > 1
    // (14485BBB0 skips player/item/dynobj). Classic 0x256 is CMSG_AUCTION_SELL_ITEM.
    if (opcode == 0x256 && size == 8)
        return AzrtRemapGuidInteract(packet, opcode);

    // 0x4C4 @ 0x144967460: u32 then guid. GetGossipText cache miss (144862A30)
    // shares this query helper. Classic CMSG_NPC_TEXT_QUERY layout.
    if (opcode == 0x4C4 && size == 12)
    {
        packet.SetOpcode(CMSG_NPC_TEXT_QUERY);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT 0x4C4 -> CMSG_NPC_TEXT_QUERY");
        return true;
    }

    // 0x287 @ 0x144969460: guid then u32. Lua SelectGossipAvailableQuest /
    // SelectAvailableQuest (Usage: strings @ 14717EC80 / 1471824A8).
    // 0x264 is the active-quest twin (SelectGossipActiveQuest).
    if ((opcode == 0x287 || opcode == 0x264) && size == 12)
    {
        packet.SetOpcode(CMSG_QUESTGIVER_QUERY_QUEST);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT 0x%X -> CMSG_QUESTGIVER_QUERY_QUEST",
                 uint32(opcode));
        return true;
    }

    // 0x74 @ 0x144964550: SelectGossipOption — guid + u32 + optional code.
    if (opcode == 0x74 && size >= 12)
    {
        packet.SetOpcode(CMSG_GOSSIP_SELECT_OPTION);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT 0x74 -> CMSG_GOSSIP_SELECT_OPTION size=%u",
                 uint32(size));
        return true;
    }

    // Movement family: shared sender 0x1449673E0, size always 0x50,
    // serialize 0x1446651D0 (u32s + u64 at +0x20). Official 0x3CD etc.
    // Do not queue as classic MSG_MOVE_* (packed guid layout).
    if (size == 80)
    {
        uint32 f0 = 0, f1 = 0, f2 = 0;
        float x = 0, y = 0, z = 0, o = 0;
        uint64 tguid = 0;
        memcpy(&f0, packet.contents() + 0x00, 4);
        memcpy(&f1, packet.contents() + 0x04, 4);
        memcpy(&f2, packet.contents() + 0x08, 4);
        memcpy(&x, packet.contents() + 0x0C, 4);
        memcpy(&y, packet.contents() + 0x10, 4);
        memcpy(&z, packet.contents() + 0x14, 4);
        memcpy(&o, packet.contents() + 0x18, 4);
        memcpy(&tguid, packet.contents() + 0x20, 8);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT MOVE80 opcode=0x%X u32=%u,%u,%u xyz=(%f,%f,%f) o=%f tguid=%s",
                 uint32(opcode), f0, f1, f2, x, y, z, o,
                 ObjectGuid(tguid).GetString().c_str());
        return false;
    }

    // u32 payload. HandleZoneUpdateOpcode ignores the value and uses server position.
    if (opcode == 0x1AB && size == 4)
    {
        packet.SetOpcode(CMSG_ZONEUPDATE);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT 0x1AB -> CMSG_ZONEUPDATE");
        return true;
    }

    // Official char-load: two C-strings (map/cinematic names). Not classic opcode 6.
    if (opcode == 0x6)
    {
        std::string a;
        std::string b;
        try
        {
            packet >> a;
            if (packet.rpos() < packet.size())
                packet >> b;
        }
        catch (...) {}
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT CMSG 0x006 size=%u a='%s' b='%s'",
                 uint32(size), a.c_str(), b.c_str());
        return false;
    }

    // Official char-load: u32 immediately before 0x006. Consume, don't parse as classic.
    if (opcode == 0x2F0 && size == 4)
    {
        uint32 value = 0;
        packet >> value;
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                 "WorldSocket: AZRT CMSG 0x2F0 u32=%u", value);
        return false;
    }

    // Classic number, extra bytes after the guid — strip to the 1.12 body.
    if (opcode == CMSG_LOGOUT_REQUEST)
    {
        packet.Initialize(CMSG_LOGOUT_REQUEST, 0);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC, "WorldSocket: AZRT 0x4B -> CMSG_LOGOUT_REQUEST");
        return true;
    }
    if (opcode == CMSG_NAME_QUERY && size >= 8)
    {
        ObjectGuid guid;
        packet.rpos(0);
        packet >> guid;
        packet.Initialize(CMSG_NAME_QUERY, 8);
        packet << guid;
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
                 "WorldSocket: AZRT 0x50 -> CMSG_NAME_QUERY guid=%s", guid.GetString().c_str());
        return true;
    }

    // Emberveil-only opcode numbers (>= 0x33C): 8-byte guid clicks.
    if (opcode >= NUM_MSG_TYPES && size == 8 && opcode != 0x4FB)
    {
        ObjectGuid guid;
        packet.rpos(0);
        packet >> guid;
        if (guid.IsCreatureOrPet())
        {
            packet.Initialize(CMSG_GOSSIP_HELLO, 8);
            packet << guid;
            packet.rpos(0);
            sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
                     "WorldSocket: AZRT 0x%X -> CMSG_GOSSIP_HELLO %s",
                     uint32(opcode), guid.GetString().c_str());
            return true;
        }
        if (guid.IsGameObject() || guid.IsMOTransport() || guid.IsTransport())
        {
            packet.Initialize(CMSG_GAMEOBJ_USE, 8);
            packet << guid;
            packet.rpos(0);
            sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
                     "WorldSocket: AZRT 0x%X -> CMSG_GAMEOBJ_USE %s",
                     uint32(opcode), guid.GetString().c_str());
            return true;
        }
        if (guid.IsPlayer())
        {
            if (opcode == 0x446)
            {
                packet.Initialize(CMSG_DUEL_ACCEPTED, 8);
                packet << guid;
            }
            else
            {
                packet.Initialize(CMSG_INSPECT, 8);
                packet << guid;
            }
            packet.rpos(0);
            sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
                     "WorldSocket: AZRT 0x%X -> %s %s",
                     uint32(opcode), LookupOpcodeName(packet.GetOpcode()),
                     guid.GetString().c_str());
            return true;
        }
    }

    // Client acks / world-state ticks. 0x234 is sent when +0x646==2 (world ready).
    if (opcode == 0x526 || opcode == 0x514 || opcode == 0x234 ||
        opcode == 0x103 || opcode == 0x511 || opcode == 0x1DC)
    {
        sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
                 "WorldSocket: AZRT ACK_CMSG opcode=0x%X size=%u",
                 uint32(opcode), uint32(size));
        return false;
    }

    if (opcode == 0x111 && size == 8)
    {
        packet.SetOpcode(CMSG_PING);
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_DETAIL, "WorldSocket: AZRT 0x111 -> CMSG_PING");
        return true;
    }

    // Same-number classic CMSG the client still emits (loot 0x15D, logout 0x4B,
    // name-query 0x50, guild, auction, ...). Body is queued as-is; parse failures
    // are skipped in ProcessIncoming, not kicked.
    if (AzrtCanPassthroughClassicCmsg(opcode, size))
    {
        packet.rpos(0);
        sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
                 "WorldSocket: AZRT PASS_CMSG opcode=%u (0x%X/%s) size=%u",
                 uint32(opcode), uint32(opcode), LookupOpcodeName(opcode), uint32(size));
        return true;
    }

    sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
             "WorldSocket: AZRT DROP_CMSG opcode=%u (0x%X) size=%u (unmapped)",
             uint32(opcode), uint32(opcode), uint32(size));
    return false;
}
} // namespace

#if defined( __GNUC__ )
#pragma pack(1)
#else
#pragma pack(push,1)
#endif
struct ServerPktHeader
{
    uint16 size;
    uint16 cmd;

    char const* data() const
    {
        return reinterpret_cast<char const*>(this);
    }

    std::size_t headerSize() const
    {
        return sizeof(ServerPktHeader);
    }
};
#if defined( __GNUC__ )
#pragma pack()
#else
#pragma pack(pop)
#endif

WorldSocket::WorldSocket(IO::Networking::AsyncSocket socket)
    : m_socket(std::move(socket)),
      m_lastPingTime(std::chrono::system_clock::time_point::min()),
      m_overSpeedPings(0),
      m_Session(nullptr),
      m_authSeed(randu32()),
      m_remoteIpAddressStringAfterProxy(m_socket.GetRemoteIpString())
{
    m_sendQueueIsRunning.clear(); // there is no atomic_flag::constructor on windows to initialize it with false by default (and if left out, linux is uninitialized and will fail randomly)
}

WorldSocket::~WorldSocket()
{
    CloseSocket();
    sLog.Out(LOG_NETWORK, LOG_LVL_BASIC, "[%s] Connection closed", GetRemoteIpString().c_str());

    if (m_sessionNoAuthTimeout)
    {
        m_sessionNoAuthTimeout->Cancel();
    }
}

void WorldSocket::DoRecvIncomingData()
{
    std::shared_ptr<ClientPktHeader> header = std::make_shared<ClientPktHeader>();

    m_socket.Read((char*)header.get(), sizeof(ClientPktHeader), [self = shared_from_this(), header](IO::NetworkError const& error, std::size_t) -> void
    {
        if (error)
        {
            if (error.GetErrorType() != IO::NetworkError::ErrorType::SocketClosed || !self->IsClosing()) // only print error if it's not "normal close" related
            {
                sLog.Out(LOG_NETWORK, LOG_LVL_BASIC, "[%s] WorldSocket::DoRecvIncomingData: IoError: %s", self->m_socket.GetRemoteIpString().c_str(), error.ToString().c_str());
                self->CloseSocket(); // This call to CloseSocket is actually necessary for once, so that others can see that this socket is not usable anymore
            }
            return;
        }

        // thread safe due to always being called from service context
        uint8 rawHeader[sizeof(ClientPktHeader)];
        memcpy(rawHeader, header.get(), sizeof(ClientPktHeader));
        self->m_Crypt.DecryptRecv((uint8*)header.get(), sizeof(ClientPktHeader));

        if (self->m_Session && self->m_Session->GetPlatform() == CLIENT_PLATFORM_X64)
        {
            // Header dump is extremely noisy during char-list poll; keep it at DETAIL.
            sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
                     "WorldSocket header raw=%02X%02X%02X%02X%02X%02X dec=%02X%02X%02X%02X%02X%02X crypt=%u",
                     rawHeader[0], rawHeader[1], rawHeader[2], rawHeader[3], rawHeader[4], rawHeader[5],
                     ((uint8*)header.get())[0], ((uint8*)header.get())[1], ((uint8*)header.get())[2],
                     ((uint8*)header.get())[3], ((uint8*)header.get())[4], ((uint8*)header.get())[5],
                     self->m_Crypt.IsInitialized() ? 1 : 0);
        }

        EndianConvertReverse(header->size);
        EndianConvert(header->cmd);

        // Emberveil uses opcodes above classic NUM_MSG_TYPES (e.g. 0x4EE char-select).
        bool const azrtSession = self->m_Session && self->m_Session->GetPlatform() == CLIENT_PLATFORM_X64;
        bool const bogusClassic = !azrtSession && IsDefinitelyBogusOpcode(static_cast<uint16>(header->cmd));
        if ((header->size < 4) || (header->size > 0x2800) || bogusClassic)
        {
            sLog.Out(LOG_NETWORK, LOG_LVL_BASIC, "[%s] WorldSocket::DoRecvIncomingData: client sent malformed packet size = %u, cmd = %u", self->m_socket.GetRemoteIpString().c_str(), header->size, header->cmd);
            self->CloseSocket(); // We don't want to receive any more packets from this client
            return;
        }

        size_t remainingPacketSize = header->size - sizeof(header->cmd);
        if (remainingPacketSize == 0)
        { // Fastpath, it's probably an OpCode without any data
            auto packet = std::make_unique<WorldPacket>(header->cmd, 0);
            if (self->_HandleCompleteReceivedPacket(std::move(packet)) == HandlerResult::Okay)
                self->DoRecvIncomingData();
        }
        else
        {
            // Allocate WorldPacket once and write into the memory inplace, no need to move or copy stuff
            // Cannot move std::unique_ptr into function capture, so it's wrapped into std::shared_ptr
            std::shared_ptr<std::unique_ptr<WorldPacket>> packetTmpSharedPtr(new std::unique_ptr<WorldPacket>(new WorldPacket(header->cmd, remainingPacketSize)));
            (*packetTmpSharedPtr)->resize(remainingPacketSize);
            self->m_socket.Read((char*)((*packetTmpSharedPtr)->contents()), (*packetTmpSharedPtr)->size(), [self, packetTmpSharedPtr](IO::NetworkError const& error, std::size_t) -> void
            {
                if (error)
                {
                    sLog.Out(LOG_BASIC, LOG_LVL_BASIC, "WorldSocket::DoRecvIncomingData: Error %s", error.ToString().c_str());
                    self->CloseSocket();
                    return;
                }

                // by std::moving the content of the shared_ptr, we will separate the unique_ptr out of the shared_ptr.
                if (self->_HandleCompleteReceivedPacket(std::move(*packetTmpSharedPtr)) == HandlerResult::Okay)
                    self->DoRecvIncomingData();
            });
        }
    });
}

WorldSocket::HandlerResult WorldSocket::_HandleCompleteReceivedPacket(std::unique_ptr<WorldPacket> packet)
{
    // Keep full opcode for AZRT (may be > 0xFFFF classic range conceptually; stored as uint16 in WorldPacket).
    uint16 const opcode = packet->GetOpcode();

    if (IsClosing())
        return HandlerResult::Fail;

    packet->FillPacketTime(WorldTimer::getMSTime());

    try
    {
        switch (opcode)
        {
            case CMSG_PING:
                return _HandlePing(*packet);
            case CMSG_AUTH_SESSION:
                if (m_Session != nullptr)
                {
                    sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::ProcessIncoming: Player send CMSG_AUTH_SESSION again");
                    return HandlerResult::Fail;
                }
                return _HandleAuthSession(*packet);
                default:
                {
                    if (m_Session == nullptr)
                    {
                        sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::ProcessIncoming: Client not authed opcode = %u", uint32(opcode));
                        return HandlerResult::Fail;
                    }

                    // AZRT/x64: always log what the client asks for (opcode + body).
                    if (m_Session->GetPlatform() == CLIENT_PLATFORM_X64)
                    {
                        char const* name = LookupOpcodeName(opcode);
                        bool const preLogin = !m_Session->GetPlayer();
                        bool const querySpam = (opcode == 0x4FB || opcode == 0x5D ||
                                                opcode == 0x143 || opcode == 0xDE);
                        sLog.Out(LOG_BASIC, querySpam ? LOG_LVL_DETAIL : LOG_LVL_BASIC,
                                 "WorldSocket: AZRT CMSG opcode=%u (0x%X) name=%s size=%u preLogin=%u account=%u body[%u]: %s",
                                 uint32(opcode), uint32(opcode), name ? name : "?",
                                 uint32(packet->size()), preLogin ? 1u : 0u, m_Session->GetAccountId(),
                                 uint32(packet->size()),
                                 packet->empty() ? "(empty)" : AzrtPacketBodyHex(*packet).c_str());
                    }
                    else
                    {
                        sLog.Out(LOG_BASIC, LOG_LVL_DETAIL, "WorldSocket: recv opcode=%u (%s) size=%u account=%u",
                                 uint32(opcode), LookupOpcodeName(opcode), uint32(packet->size()), m_Session->GetAccountId());
                    }

                    // Emberveil C->S opcode map (client ctor 0x144124C80 + installer globals):
                    //   0x060 -> CMSG_CHAR_ENUM
                    //   0x111 -> CMSG_PING (global 0x148142358)
                    //   0x299 -> CMSG_CHAR_CREATE
                    //   0x221 -> CMSG_CHAR_DELETE
                    //   0x4EE -> CMSG_PLAYER_LOGIN — u64 guid + CString locale
                    //   0x011 -> CMSG_SET_ACTIVE_MOVER (8B guid)
                    //   0x159 / 0x47E -> CMSG_SET_SELECTION (8B guid)
                    //   0x256 -> CMSG_GOSSIP_HELLO / CMSG_GAMEOBJ_USE
                    //   0x4C4 -> CMSG_NPC_TEXT_QUERY (u32 + guid)
                    //   0x287 / 0x264 -> CMSG_QUESTGIVER_QUERY_QUEST (guid + u32)
                    //   0x74 -> CMSG_GOSSIP_SELECT_OPTION
                    //   size=80 -> movement family (drop; log xyz)
                    //   0x1AB -> CMSG_ZONEUPDATE (u32)
                    //   0x4FB / 0x5D / 0x143 / 0xDE -> name/creature/GO/item query
                    // Unmapped in-world CMSG are dropped (numbers collide with classic SMSG).
                    if (m_Session->GetPlatform() == CLIENT_PLATFORM_X64)
                    {
                        if (opcode == 0x60 && packet->size() == 0)
                        {
                            // Official also emits empty 0x60 after enter-world (HUD init).
                            // Answering with 0x478 CHAR_ENUM while in-world unloads the map.
                            Player* plr = m_Session->GetPlayer();
                            if (plr && plr->IsInWorld())
                            {
                                sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                                         "WorldSocket: AZRT 0x60 in-world (not CHAR_ENUM)");
                                return HandlerResult::Okay;
                            }
                            sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                                     "WorldSocket: AZRT 0x60 -> CMSG_CHAR_ENUM");
                            m_Session->HandleCharEnumOpcode(NullClientPacket(CMSG_CHAR_ENUM));
                            return HandlerResult::Okay;
                        }

                        if (opcode == 0x111 && packet->size() == 8)
                        {
                            sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                                     "WorldSocket: AZRT 0x111 -> CMSG_PING");
                            packet->SetOpcode(CMSG_PING);
                            return _HandlePing(*packet);
                        }

                        // Enter-world: guid + locale. Dropping this left the client in free-fly
                        // with no spawned player (local scene without LOGIN_VERIFY / updates).
                        if (opcode == 0x4EE && packet->size() >= 8)
                        {
                            uint32 const pktSize = uint32(packet->size());
                            ObjectGuid guid;
                            *packet >> guid;
                            sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                                     "WorldSocket: AZRT 0x4EE -> CMSG_PLAYER_LOGIN guid=%u size=%u",
                                     guid.GetCounter(), pktSize);
                            if (guid.IsPlayer())
                                m_Session->LoginPlayer(guid);
                            return HandlerResult::Okay;
                        }

                        if (opcode == 0x299)
                        {
                            // Emberveil CMSG 0x299 — not classic CMSG_CHAR_CREATE (54).
                            // Body: UTF-8 CString name + 9×u8 appearance. Do not queue
                            // the wire opcode through the 1.12 reader.
                            try
                            {
                                auto create = std::make_unique<WorldPackets::Character::CharCreate>();
                                *packet >> create->name;
                                *packet >> create->race >> create->class_ >> create->gender
                                        >> create->skin >> create->face >> create->hairStyle
                                        >> create->hairColor >> create->facialHair >> create->outfitId;
                                sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                                         "WorldSocket: AZRT 0x299 CHAR_CREATE name=%s race=%u class=%u gender=%u size=%u unread=%u",
                                         create->name.c_str(), uint32(create->race), uint32(create->class_),
                                         uint32(create->gender), uint32(packet->size()),
                                         uint32(packet->size() - packet->rpos()));
                                m_Session->QueuePacket(std::move(create));
                            }
                            catch (ByteBufferException&)
                            {
                                sLog.Out(LOG_BASIC, LOG_LVL_ERROR,
                                         "WorldSocket: AZRT 0x299 CHAR_CREATE parse fail size=%u",
                                         uint32(packet->size()));
                            }
                            return HandlerResult::Okay;
                        }
                        else if (opcode == 0x221)
                        {
                            sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                                     "WorldSocket: AZRT 0x221 -> CMSG_CHAR_DELETE size=%u",
                                     uint32(packet->size()));
                            packet->SetOpcode(CMSG_CHAR_DELETE);
                        }
                        else if (m_Session->GetPlayer())
                        {
                            uint16 const wireOp = packet->GetOpcode();
                            if (!AzrtRemapInWorldCmsg(*packet, m_Session))
                            {
                                if (wireOp == 0x103)
                                    m_Session->AzrtContinueEnterWorld();
                                return HandlerResult::Okay;
                            }
                        }
                        else if (!m_Session->GetPlayer() && opcode != CMSG_PING &&
                                 opcode != CMSG_CHAR_CREATE && opcode != CMSG_CHAR_DELETE &&
                                 opcode != CMSG_PLAYER_LOGIN)
                        {
                            // Unmapped AZRT pre-login opcodes (>=0x300 etc.) — drop, never kick.
                            if (opcode >= 0x300)
                            {
                                sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                                         "WorldSocket: AZRT action=DROP_PRELOGIN opcode=%u (0x%X)",
                                         uint32(opcode), uint32(opcode));
                                return HandlerResult::Okay;
                            }
                        }
                    }

                    // AZRT/x64 pre-login: drop remaining colliding/unknown opcodes; never kick.
                    if (m_Session->GetPlatform() == CLIENT_PLATFORM_X64 && !m_Session->GetPlayer())
                    {
                        uint16 const op = packet->GetOpcode();
                        if (op != CMSG_PING && op != CMSG_CHAR_CREATE && op != CMSG_CHAR_DELETE &&
                            op != CMSG_CHAR_ENUM && op != CMSG_PLAYER_LOGIN)
                        {
                            sLog.Out(LOG_BASIC, LOG_LVL_BASIC,
                                     "WorldSocket: AZRT action=DROP_PRELOGIN opcode=%u (0x%X)",
                                     uint32(op), uint32(op));
                            return HandlerResult::Okay;
                        }
                    }

                    // AZRT in-world: unknown opcodes are not classic handlers — drop, don't ERROR-spam.
                    if (m_Session->GetPlatform() == CLIENT_PLATFORM_X64)
                    {
                        OpcodeHandler const& h = LookupOpcodeHandler(packet->GetOpcode());
                        if (!h.impl.has_value())
                        {
                            sLog.Out(LOG_BASIC, LOG_LVL_DETAIL,
                                     "WorldSocket: AZRT DROP_CMSG opcode=%u (0x%X) size=%u (no handler)",
                                     uint32(packet->GetOpcode()), uint32(packet->GetOpcode()),
                                     uint32(packet->size()));
                            return HandlerResult::Okay;
                        }
                    }

                    try
                    {
                        m_Session->QueueBinaryPacket(std::move(packet));
                    }
                    catch (ByteBufferException&)
                    {
                        sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket: skipped malformed opcode=%u size parse failure from %s account=%u",
                                 uint32(opcode), GetRemoteIpString().c_str(), m_Session->GetAccountId());
                    }
                    return HandlerResult::Okay;
                }
        }
    }
    catch (ByteBufferException&)
    {
        sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::ProcessIncoming ByteBufferException occured while parsing an instant handled packet (opcode: %u) from client %s, accountid=%i.", opcode, GetRemoteIpString().c_str(), m_Session ? m_Session->GetAccountId() : -1);

        if (sLog.HasLogLevelOrHigher(LOG_LVL_DEBUG))
        {
            sLog.Out(LOG_BASIC, LOG_LVL_DEBUG, "Dumping error-causing packet:");
            packet->PrintAsHex();
        }

        if (sWorld.getConfig(CONFIG_BOOL_KICK_PLAYER_ON_BAD_PACKET))
        {
            sLog.Out(LOG_BASIC, LOG_LVL_DETAIL, "Disconnecting session [account id %i / address %s] for badly formatted packet.",
                       m_Session ? m_Session->GetAccountId() : -1, GetRemoteIpString().c_str());

            return HandlerResult::Fail;
        }

        return HandlerResult::Okay;
    }
}

/// This function will resolve the ip-address of the current host
/// For example if you hostname is called "world.mycoolserver.com" and it points to 123.45.66.7 it will be added to the server list
/// Also 127.0.0.1 will be added as a fallback
/// This list is later used to determine if clients try to connect to this server without registering at realmd first
static std::set<std::string> GetServerAddresses()
{
    std::set<std::string> addresses;
    addresses.insert("127.0.0.1");

    std::string myHostname = IO::Networking::DNS::GetOwnHostname();
    std::vector<IO::Networking::IpAddress> ipAddresses = IO::Networking::DNS::ResolveDomainAll(myHostname, IO::Networking::IpAddress::Type::IPv4);
    for (auto const& ipAddress : ipAddresses)
    {
        addresses.insert(ipAddress.ToString());
    }

    return addresses;
}

WorldSocket::HandlerResult WorldSocket::_HandleAuthSession(WorldPacket& recvPacket)
{
    Crypto::Hash::SHA1::Digest digest;
    uint32 clientSeed;
    uint32 serverId;
    uint32 clientBuild;
    uint32 accountId;
    AccountTypes security;
    LocaleConstant locale;
    std::string account, os, platform;
    BigNumber K;
    WorldPacket packet, addonPacket;
    static std::set<std::string> const serverAddressList = GetServerAddresses();

    // Read the content of the packet
    recvPacket >> clientBuild;
    recvPacket >> serverId;
    recvPacket >> account;

    recvPacket >> clientSeed;
    recvPacket.read(digest.data(), digest.size());

    sLog.Out(LOG_BASIC, LOG_LVL_DEBUG, "WorldSocket::HandleAuthSession: client %u, serverId %u, account %s, clientseed %u",
              clientBuild,
              serverId,
              account.c_str(),
              clientSeed);

    // Check the version of client trying to connect
    if (!IsAcceptableClientBuild(clientBuild))
    {
        packet.Initialize(SMSG_AUTH_RESPONSE, 1);
        packet << uint8(AUTH_VERSION_MISMATCH);

        SendPacket(packet);

        sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::HandleAuthSession: Sent Auth Response (version mismatch).");
        return HandlerResult::Fail;
    }

    // Get the account information from the realmd database
    std::string safe_account = account; // Duplicate, else will screw the SHA hash verification below
    LoginDatabase.escape_string(safe_account);
    // No SQL injection, username escaped.
    auto accountQueryResult =
        LoginDatabase.PQuery("SELECT "
                             "a.`id`, "             // 0
                             "aa.`gmLevel`, "       // 1
                             "a.`sessionkey`, "     // 2
                             "a.`last_ip`, "        // 3
                             "a.`v`, "              // 4
                             "a.`s`, "              // 5
                             "a.`mutetime`, "       // 6
                             "a.`locale`, "         // 7
                             "a.`os`, "             // 8
                             "a.`platform`, "       // 9
                             "a.`flags`, "          // 10
                             "a.`email`, "          // 11
                             "a.`email_verif`, "    // 12
                             "ab.`unbandate` > UNIX_TIMESTAMP() OR ab.`unbandate` = ab.`bandate` " // 13
                             "FROM `account` a "
                             "LEFT JOIN `account_access` aa ON a.`id` = aa.`id` AND aa.`RealmID` IN (-1, %u) "
                             "LEFT JOIN `account_banned` ab ON a.`id` = ab.`id` AND ab.`active` = 1 WHERE a.`username` = '%s' && DATEDIFF(NOW(), a.`last_login`) < 1 "
                             "ORDER BY aa.`RealmID` DESC LIMIT 1", realmID, safe_account.c_str());

    // Stop if the account is not found
    if (!accountQueryResult)
    {
        packet.Initialize(SMSG_AUTH_RESPONSE, 1);
        packet << uint8(AUTH_UNKNOWN_ACCOUNT);

        SendPacket(packet);

        sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::HandleAuthSession: Sent Auth Response (unknown account).");
        return HandlerResult::Fail;
    }

    Field* fields = accountQueryResult->Fetch();

    // Prevent connecting directly to mangosd by checking
    // that same ip connected to realmd previously.
    if (fields[3].GetCppString() != GetRemoteIpString() && serverAddressList.find(GetRemoteIpString()) == serverAddressList.end())
    {
        packet.Initialize(SMSG_AUTH_RESPONSE, 1);
        packet << uint8(AUTH_FAILED);
        SendPacket(packet);

        sLog.Out(LOG_BASIC, LOG_LVL_BASIC, "WorldSocket::HandleAuthSession: Sent Auth Response (Account IP differs from realmd).");
        return HandlerResult::Fail;
    }

    accountId = fields[0].GetUInt32();
    security = fields[1].GetString() ? (AccountTypes)(fields[1].GetUInt32()) : SEC_PLAYER;
    if (security > SEC_ADMINISTRATOR) // prevent invalid security settings in DB
        security = SEC_ADMINISTRATOR;

    K.SetHexStr(fields[2].GetString());
    if (K.AsByteArray().empty())
        return HandlerResult::Fail;

    time_t mutetime = time_t(fields[6].GetUInt64());
    locale = LocaleConstant(fields[7].GetUInt8());
    if (locale >= MAX_LOCALE)
        locale = LOCALE_enUS;
    os = fields[8].GetCppString();
    platform = fields[9].GetCppString();
    uint32 accFlags = fields[10].GetUInt32();
    std::string email = fields[11].GetCppString();
    bool verifiedEmail = fields[12].GetBool() || email.empty(); // treat no email as verified (created from console)
    bool isBanned = fields[13].GetBool();

    if (isBanned || sAccountMgr.IsIPBanned(GetRemoteIpString()))
    {
        packet.Initialize(SMSG_AUTH_RESPONSE, 1);
        packet << uint8(AUTH_BANNED);
        SendPacket(packet);

        sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::HandleAuthSession: Sent Auth Response (Account banned).");
        return HandlerResult::Fail;
    }

    // Check locked state for server
    AccountTypes allowedAccountType = sWorld.GetPlayerSecurityLimit();

    if (allowedAccountType > SEC_PLAYER && security < allowedAccountType)
    {
        packet.Initialize(SMSG_AUTH_RESPONSE, 1);
        packet << uint8(AUTH_UNAVAILABLE);
        SendPacket(packet);

        sLog.Out(LOG_BASIC, LOG_LVL_BASIC, "WorldSocket::HandleAuthSession: User tries to login but his security level is not enough");
        return HandlerResult::Fail;
    }

    // Check that Key and account name are the same on client and server
    Crypto::Hash::SHA1::Generator sha;

    uint32 t = 0;
    uint32 seed = m_authSeed;

    sha.UpdateData(account);
    sha.UpdateData((uint8 *) &t, 4);
    sha.UpdateData((uint8 *) &clientSeed, 4);
    sha.UpdateData((uint8 *) &seed, 4);
    sha.UpdateData(K);
    auto expectedDigest = sha.GetDigest();

    if (digest != expectedDigest)
    {
        packet.Initialize(SMSG_AUTH_RESPONSE, 1);
        packet << uint8(AUTH_FAILED);
        SendPacket(packet);

        sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::HandleAuthSession: Sent Auth Response (authentification failed), account ID: %u.", accountId);
        return HandlerResult::Fail;
    }

    std::string address = GetRemoteIpString();

    sLog.Out(LOG_BASIC, LOG_LVL_DEBUG, "WorldSocket::HandleAuthSession: Client '%s' authenticated successfully from %s.",
              account.c_str(),
              address.c_str());

    // Update the last_ip in the database
    // No SQL injection, username escaped.
    static SqlStatementID updAccount;

    SqlStatement stmt = LoginDatabase.CreateStatement(updAccount, "UPDATE `account` SET `last_ip` = ? WHERE `username` = ?");
    stmt.PExecute(address.c_str(), account.c_str());

    ClientOSType clientOs;
    if (os == "Win")
        clientOs = CLIENT_OS_WIN;
    else if (os == "OSX")
        clientOs = CLIENT_OS_MAC;
    else
    {
        sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::HandleAuthSession: Unrecognized OS '%s' for account '%s' from %s", os.c_str(), account.c_str(), address.c_str());
        return HandlerResult::Fail;
    }

    ClientPlatformType clientPlatform;
    if (platform == "x86")
        clientPlatform = CLIENT_PLATFORM_X86;
    else if (platform == "x64") // Unreal Azeroth / Emberveil (AZRT)
        clientPlatform = CLIENT_PLATFORM_X64;
    else if (platform == "PPC" && clientOs == CLIENT_OS_MAC)
        clientPlatform = CLIENT_PLATFORM_PPC;
    else
    {
        sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::HandleAuthSession: Unrecognized Platform '%s' for account '%s' from %s", platform.c_str(), account.c_str(), address.c_str());
        return HandlerResult::Fail;
    }

    sLog.Out(LOG_BASIC, LOG_LVL_BASIC, "WorldSocket::HandleAuthSession: account='%s' id=%u build=%u os=%s platform=%s",
             account.c_str(), accountId, clientBuild, os.c_str(), platform.c_str());


    // ===== Auth was successful =====
    if (this->m_sessionNoAuthTimeout)
    {
        this->m_sessionNoAuthTimeout->Cancel();
        this->m_sessionNoAuthTimeout = nullptr;
    }

    m_Session = new WorldSession(accountId, this->shared_from_this(), security, mutetime, locale);

    m_Crypt.SetKey(K.AsByteArray());
    m_Crypt.Init();

    m_Session->SetUsername(account);
    m_Session->SetGameBuild(clientBuild);
    m_Session->SetAccountFlags(accFlags);
    m_Session->SetOS(clientOs);
    m_Session->SetPlatform(clientPlatform);
    m_Session->SetVerifiedEmail(verifiedEmail);
    m_Session->SetSessionKey(K);
    m_Session->LoadGlobalAccountData();
    m_Session->LoadTutorialsData();
    sAccountMgr.UpdateAccountData(accountId, account, email, verifiedEmail, security);

    sWorld.AddSession(m_Session);

    // Emberveil has no classic addon handshake; sending SMSG_ADDON_INFO before AUTH_OK
    // desyncs its decrypt stream and character list never appears.
    if (clientPlatform != CLIENT_PLATFORM_X64)
    {
        if (sAddOnHandler.BuildAddonPacket(&recvPacket, &addonPacket))
            SendPacket(addonPacket);
    }
    else
    {
        sLog.Out(LOG_BASIC, LOG_LVL_BASIC, "WorldSocket::HandleAuthSession: skipping addon packet for AZRT/x64");
    }

    return HandlerResult::Okay;
}

WorldSocket::HandlerResult WorldSocket::_HandlePing(WorldPacket& recvPacket)
{
    uint32 ping;
#if SUPPORTED_CLIENT_BUILD > CLIENT_BUILD_1_8_4
    uint32 latency;
#endif

    // Get the ping packet content
    recvPacket >> ping;
#if SUPPORTED_CLIENT_BUILD > CLIENT_BUILD_1_8_4
    recvPacket >> latency;
#endif

    if (m_lastPingTime == std::chrono::system_clock::time_point::min())
        m_lastPingTime = std::chrono::system_clock::now();              // for 1st ping
    else
    {
        auto now = std::chrono::system_clock::now();
        std::chrono::seconds seconds = std::chrono::duration_cast<std::chrono::seconds>(now - m_lastPingTime);
        m_lastPingTime = now;

        if (seconds.count() < 27)
        {
            ++m_overSpeedPings;

            uint32 maxAllowedOverspeedPings = sWorld.getConfig(CONFIG_UINT32_MAX_OVERSPEED_PINGS);
            if (maxAllowedOverspeedPings && m_overSpeedPings > maxAllowedOverspeedPings)
            {
                if (m_Session && m_Session->GetSecurity() == SEC_PLAYER)
                {
                    sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::HandlePing: Player kicked for overspeeded pings address = %s", GetRemoteIpString().c_str());
                    return HandlerResult::Fail;
                }
            }
        }
        else
        {
            m_overSpeedPings = 0;
        }
    }

    // critical section
    {
        if (m_Session)
        {
#if SUPPORTED_CLIENT_BUILD > CLIENT_BUILD_1_8_4
            m_Session->SetLatency(latency);
#endif
        }
        else
        {
            sLog.Out(LOG_BASIC, LOG_LVL_ERROR, "WorldSocket::HandlePing: peer sent CMSG_PING, but is not authenticated or got recently kicked, address = %s", GetRemoteIpString().c_str());
            return HandlerResult::Fail;
        }
    }

    WorldPacket packet(SMSG_PONG, 4);
    packet << ping;
    SendPacket(packet);

    return HandlerResult::Okay;
}

void WorldSocket::SendInitialPacketAndStartRecvLoop()
{
    // Send startup packet.
    WorldPacket packet(SMSG_AUTH_CHALLENGE, 4);
    packet << m_authSeed;

    SendPacket(packet);

    DoRecvIncomingData();
}

void WorldSocket::SendPacket(WorldPacket packet)
{
    if (IsClosing())
        return;

    // We don't want to allocate or encrypt anything inside the world thread, so we move everything to the IO thread.
    m_sendQueueLock.lock();
    if (m_sendQueue.size() > 1024) // There should never be so many packets queued up. The socket is probably not responding.
    {
        m_sendQueueLock.unlock();
        sLog.Out(LOG_NETWORK, LOG_LVL_ERROR, "[%s] Send queue is full. Disconnecting.", GetRemoteIpString().c_str());
        CloseSocket();
        return;
    }
    m_sendQueue.push(std::move(packet));
    // The flag must be set under the same lock that guards the queue: HandleResultOfAsyncWrite
    // only clears it while holding the lock with an empty queue, so our push is either seen by
    // the running loop or we observe the cleared flag and start a new one. Otherwise a packet
    // pushed between its empty-check and clear would strand in the queue until the next send.
    bool const alreadyRunning = m_sendQueueIsRunning.test_and_set();
    m_sendQueueLock.unlock();

    // Start AsyncProcessingSendQueue which take things from the queue
    if (alreadyRunning)
        return; // already running

    m_socket.EnterIoContext([self = shared_from_this()](IO::NetworkError error)
    {
        self->HandleResultOfAsyncWrite(error, std::make_shared<ByteBuffer>());
    });
}

void WorldSocket::HandleResultOfAsyncWrite(IO::NetworkError const& error, std::shared_ptr<ByteBuffer> const& alreadyAllocatedBuffer)
{
    if (error)
    {
        if (error.GetErrorType() != IO::NetworkError::ErrorType::SocketClosed || !IsClosing()) // only print error if it's not "normal close" related
        {
            sLog.Out(LOG_NETWORK, LOG_LVL_ERROR, "[%s] WorldSocket::HandleResultOfAsyncWrite: IoError: %s", GetRemoteIpString().c_str(), error.ToString().c_str());
            CloseSocket(); // This call to CloseSocket is actually necessary for once, so that others can see that this socket is not usable anymore
        }

        m_sendQueueIsRunning.clear();
        return;
    }

    m_sendQueueLock.lock();
    if (m_sendQueue.empty())
    {
        // Must be cleared while holding the queue lock, see comment in SendPacket().
        m_sendQueueIsRunning.clear();
        m_sendQueueLock.unlock();
        return;
    }
    m_sendQueueLock.unlock();

    // Combine all packets into `alreadyAllocatedBuffer`
    alreadyAllocatedBuffer->clear();
    while (!m_sendQueue.empty())
    {
        m_sendQueueLock.lock();
        if (m_sendQueue.empty()) // re-check after we locked the queue if it's really not empty
        {
            m_sendQueueLock.unlock();
            break;
        }
        WorldPacket packet = std::move(m_sendQueue.front());
        m_sendQueue.pop();
        m_sendQueueLock.unlock();

        ServerPktHeader header{};

        header.cmd = packet.GetOpcode();
        EndianConvert(header.cmd);

        header.size = static_cast<uint16>(packet.size() + 2);
        EndianConvertReverse(header.size);

        m_Crypt.EncryptSend(reinterpret_cast<uint8*>(&header), sizeof(header)); // in vanilla versions of the game only the header is encrypted

        alreadyAllocatedBuffer->append(header.data(), header.headerSize());
        if (!packet.empty())
            alreadyAllocatedBuffer->append(packet.contents(), packet.size());
    }

    m_socket.Write({ alreadyAllocatedBuffer /* dont move, re-used in lambda */ }, [self = shared_from_this(), alreadyAllocatedBuffer](IO::NetworkError const& error)
    {
        self->HandleResultOfAsyncWrite(error, alreadyAllocatedBuffer);
    });
}

void WorldSocket::Start()
{
    // Start auto timeout loop
    if (int secs = sConfig.GetIntDefault("Network.TimeoutSecsIfNoAuth", 10))
    {
        m_sessionNoAuthTimeout = sAsyncSystemTimer.ScheduleFunctionOnce(std::chrono::seconds(secs), [this]()
        {
            sLog.Out(LOG_NETWORK, LOG_LVL_DETAIL, "[%s] Connection has reached TimeoutSecsIfNoAuth. Closing socket...", this->GetRemoteIpString().c_str());
            // It's correct that we capture _this_ and not a shared_ptr, since the timer will be canceled in destructor
            this->CloseSocket();
        });
    }

    SendInitialPacketAndStartRecvLoop();
}

void WorldSocket::CloseSocket()
{
    m_socket.CloseSocket();
}
