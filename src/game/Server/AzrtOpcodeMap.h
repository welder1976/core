/*
 * Native AZRT (Unreal Azeroth / Emberveil) opcode map for vmangos.
 *
 * Adapted from Unreal-Open-Azeroth OpcodeMap.h / WorldPipe.cpp, then
 * aligned to Emberveil's runtime Register map (WorldVerifyProbe, RVA
 * 0x495E430). UOA talks to stock mangos and stops at char-select; we keep
 * their remap (0x478 enum, 0x232/0x233 create/delete) and speak the rest
 * natively. Official enter: 0x527 access, 0xC5 VERIFY, CMSG 0x103,
 * 0x28E/0x1FC. No 0x102. Player spawn is the first 0x1FC CREATE.
 */

#ifndef MANGOS_AZRT_OPCODE_MAP_H
#define MANGOS_AZRT_OPCODE_MAP_H

#include "Opcodes.h"

namespace AzrtOpcode
{
    // Emberveil S->C (live handlers). Classic numbers that differ are remapped
    // in WorldSession::SendPacketImpl.
    enum Server : uint16
    {
        CHAR_ENUM           = 0x478,
        CHAR_CREATE         = 0x232,
        CHAR_DELETE         = 0x233,
        CHAR_RENAME         = 0x3C3,
        LOGIN_FAILED        = 0x216,
        MAP_VERIFY          = 0x0C5, // SMSG_LOGIN_VERIFY_WORLD
        COMPRESSED_UPDATE   = 0x1FC, // SMSG_(COMPRESSED_)UPDATE_OBJECT
        INITIAL_SPELLS      = 0x2EB,
        ACTION_BUTTONS      = 0x4FA,
        BINDPOINT           = 0x477,
        INIT_FACTIONS       = 0x2EE,
        LOGIN_SETTIMESPEED  = 0x2D7,
        INIT_WORLD_STATES   = 0x200,
        QUERY_TIME          = 0x172,
        CREATURE_QUERY      = 0x509,
        GAMEOBJECT_QUERY    = 0x04F,
        ITEM_QUERY          = 0x294,
        GOSSIP_MESSAGE      = 0x0A0,
        QUERY_NAME          = 0x3CC, // official 0x4FB reply
        WORLD_ACCESS        = 0x527  // official sniff 1319: 01 00 00 00 00
    };

    // Emberveil C->S (WorldSocket remaps). Auth/ping keep classic numbers.
    enum Client : uint16
    {
        CMSG_CHAR_LIST         = 0x060,
        CMSG_PING              = 0x111,
        CMSG_CHAR_CREATE       = 0x299,
        CMSG_CHAR_DELETE       = 0x221,
        CMSG_PLAYER_LOGIN      = 0x4EE,
        CMSG_SET_MOVER         = 0x011, // after local-player CREATE: take control (NPC guid = walk notify)
        CMSG_SET_SELECTION     = 0x159,
        CMSG_ZONEUPDATE        = 0x1AB,
        CMSG_WORLD_READY       = 0x103, // ack after 0xC5; not forwarded as SMSG_EMOTE
        CMSG_QUERY_BY_GUID     = 0x4FB,
        CMSG_CREATURE_QUERY    = 0x05D, // live: 3098/3143/… (Frida had this inverted)
        CMSG_ITEM_QUERY        = 0x0DE, // live: equipped 139/140/12282
        CMSG_GAMEOBJECT_QUERY  = 0x143
    };

    // UOA WorldPipe: classic movement/spell bodies corrupt the UE actor.
    inline bool DropUnsafeClassicBody(uint16 op)
    {
        switch (op)
        {
            case SMSG_MONSTER_MOVE:
            case SMSG_MONSTER_MOVE_TRANSPORT:
            case SMSG_SPELL_START:
            case SMSG_SPELL_GO:
            case SMSG_SPLINE_MOVE_ROOT:
            case SMSG_SPLINE_MOVE_UNROOT:
            case SMSG_SPLINE_MOVE_FEATHER_FALL:
            case SMSG_SPLINE_MOVE_NORMAL_FALL:
            case SMSG_SPLINE_MOVE_SET_HOVER:
            case SMSG_SPLINE_MOVE_UNSET_HOVER:
            case SMSG_SPLINE_MOVE_WATER_WALK:
            case SMSG_SPLINE_MOVE_LAND_WALK:
            case SMSG_SPLINE_MOVE_START_SWIM:
            case SMSG_SPLINE_MOVE_STOP_SWIM:
            case SMSG_SPLINE_MOVE_SET_RUN_MODE:
            case SMSG_SPLINE_MOVE_SET_WALK_MODE:
            case SMSG_DESTROY_OBJECT:
            case SMSG_NEW_WORLD:
            case SMSG_ACCOUNT_DATA_MD5: // rewritten as 0x2AC×N
                return true;
            default:
                return false;
        }
    }

    // Simple S->C number remap. UPDATE_OBJECT still needs zlib wrapping in the caller.
    // Returns the wire opcode (may equal `op`).
    inline uint16 RemapServerOpcode(uint16 op)
    {
        switch (op)
        {
            case SMSG_COMPRESSED_UPDATE_OBJECT:
            case SMSG_UPDATE_OBJECT:             return COMPRESSED_UPDATE;
            case SMSG_INITIAL_SPELLS:            return INITIAL_SPELLS;
            case SMSG_ACTION_BUTTONS:            return ACTION_BUTTONS;
            case SMSG_CHAR_ENUM:                 return CHAR_ENUM;
            case SMSG_CHAR_CREATE:               return CHAR_CREATE;
            case SMSG_CHAR_DELETE:               return CHAR_DELETE;
            case SMSG_CHAR_RENAME:               return CHAR_RENAME;
            case SMSG_CHARACTER_LOGIN_FAILED:    return LOGIN_FAILED;
            case SMSG_LOGIN_VERIFY_WORLD:        return MAP_VERIFY;
            case SMSG_LOGIN_SETTIMESPEED:        return LOGIN_SETTIMESPEED;
            case SMSG_BINDPOINTUPDATE:           return BINDPOINT;
            case SMSG_INITIALIZE_FACTIONS:       return INIT_FACTIONS;
            case SMSG_GAMEOBJECT_QUERY_RESPONSE: return GAMEOBJECT_QUERY;
            case SMSG_CREATURE_QUERY_RESPONSE:   return CREATURE_QUERY;
            case SMSG_ITEM_QUERY_SINGLE_RESPONSE:return ITEM_QUERY;
            case SMSG_INIT_WORLD_STATES:         return INIT_WORLD_STATES;
            case SMSG_QUERY_TIME_RESPONSE:       return QUERY_TIME;
            case SMSG_GOSSIP_MESSAGE:            return GOSSIP_MESSAGE;
            default:                             return op;
        }
    }

    // WorldVerifyProbe Register helper RVA 0x495E430 (ImageBase 0x140000000): 330
    // natively registered SMSG. Never registered: 0x236 / 0x061 / 0x096 / 0x2C2.
    // Stub handler RVA 0x10EAF60: 0x001, 0x210, 0x284, 0x2D4, 0x337.
    // Extra (other dispatcher): auth 0x1EC/0x1EE, charlist 0x216/0x232/0x233/0x3C3/0x478,
    // injected bind stub 0x2A7.
    inline bool IsLiveSmsg(uint16 op)
    {
        switch (op)
        {
            case 0x001: case 0x003: case 0x004: case 0x005: case 0x007: case 0x009: case 0x00E: case 0x012:
            case 0x017: case 0x01A: case 0x01B: case 0x01F: case 0x024: case 0x028: case 0x02F: case 0x03B:
            case 0x046: case 0x049: case 0x04A: case 0x04B: case 0x04C: case 0x04D: case 0x04F: case 0x052:
            case 0x05E: case 0x06E: case 0x070: case 0x073: case 0x076: case 0x07A: case 0x07E: case 0x080:
            case 0x084: case 0x08A: case 0x091: case 0x094: case 0x095: case 0x0A0: case 0x0A2: case 0x0A4:
            case 0x0A9: case 0x0AB: case 0x0AF: case 0x0B1: case 0x0B8: case 0x0BB: case 0x0BC: case 0x0C4:
            case 0x0C5: case 0x0CC: case 0x0D0: case 0x0D1: case 0x0D5: case 0x0DD: case 0x0E0: case 0x0E2:
            case 0x0E4: case 0x0E5: case 0x0EB: case 0x0F0: case 0x0FA: case 0x0FC: case 0x102: case 0x106:
            case 0x108: case 0x116: case 0x117: case 0x11A: case 0x121: case 0x125: case 0x12E: case 0x131:
            case 0x132: case 0x135: case 0x136: case 0x137: case 0x13B: case 0x13E: case 0x140: case 0x141:
            case 0x148: case 0x149: case 0x14A: case 0x14F: case 0x15E: case 0x163: case 0x169: case 0x16F:
            case 0x172: case 0x177: case 0x17A: case 0x17D: case 0x186: case 0x18A: case 0x18B: case 0x18C:
            case 0x194: case 0x19B: case 0x1A1: case 0x1A7: case 0x1AF: case 0x1B0: case 0x1B2: case 0x1B6:
            case 0x1BC: case 0x1BD: case 0x1BF: case 0x1C2: case 0x1C6: case 0x1CA: case 0x1CE: case 0x1D2:
            case 0x1D3: case 0x1DD: case 0x1E0: case 0x1E4: case 0x1E5: case 0x1E6: case 0x1EC: case 0x1EE:
            case 0x1F8: case 0x1FA: case 0x1FC: case 0x200: case 0x204: case 0x210: case 0x212: case 0x216:
            case 0x21A: case 0x220: case 0x226: case 0x232: case 0x233: case 0x23B: case 0x23E: case 0x243:
            case 0x246: case 0x24A: case 0x24E: case 0x24F: case 0x251: case 0x253: case 0x261: case 0x268:
            case 0x26F: case 0x271: case 0x273: case 0x27B: case 0x27C: case 0x27E: case 0x280: case 0x284:
            case 0x288: case 0x28A: case 0x28C: case 0x28E: case 0x294: case 0x29A: case 0x29B: case 0x29C:
            case 0x2A2: case 0x2A3: case 0x2A4: case 0x2A5: case 0x2A7: case 0x2A8: case 0x2AA: case 0x2AB:
            case 0x2AC: case 0x2B1: case 0x2B3: case 0x2B4: case 0x2B8: case 0x2BD: case 0x2C3: case 0x2C5:
            case 0x2C6: case 0x2CA: case 0x2CC: case 0x2CD: case 0x2CF: case 0x2D4: case 0x2D5: case 0x2D7:
            case 0x2D9: case 0x2DA: case 0x2E2: case 0x2E5: case 0x2E8: case 0x2EB: case 0x2EE: case 0x2F2:
            case 0x2FA: case 0x2FB: case 0x2FC: case 0x2FD: case 0x2FF: case 0x300: case 0x302: case 0x307:
            case 0x308: case 0x309: case 0x30C: case 0x311: case 0x313: case 0x31D: case 0x321: case 0x325:
            case 0x32E: case 0x332: case 0x334: case 0x335: case 0x336: case 0x337: case 0x33F: case 0x343:
            case 0x349: case 0x34B: case 0x352: case 0x355: case 0x356: case 0x35F: case 0x36D: case 0x376:
            case 0x37C: case 0x381: case 0x385: case 0x38B: case 0x38D: case 0x393: case 0x395: case 0x39A:
            case 0x39E: case 0x39F: case 0x3A0: case 0x3AC: case 0x3AE: case 0x3B3: case 0x3B6: case 0x3B7:
            case 0x3B9: case 0x3BC: case 0x3BF: case 0x3C1: case 0x3C3: case 0x3C5: case 0x3CA: case 0x3CC:
            case 0x3CD: case 0x3D1: case 0x3D2: case 0x3D7: case 0x3DD: case 0x3E1: case 0x3E9: case 0x3F9:
            case 0x400: case 0x404: case 0x406: case 0x40D: case 0x411: case 0x413: case 0x417: case 0x41B:
            case 0x41C: case 0x41D: case 0x422: case 0x425: case 0x42A: case 0x42D: case 0x435: case 0x439:
            case 0x43A: case 0x448: case 0x44E: case 0x452: case 0x459: case 0x466: case 0x469: case 0x46B:
            case 0x46C: case 0x46D: case 0x46F: case 0x470: case 0x471: case 0x473: case 0x475: case 0x477:
            case 0x478: case 0x47C: case 0x484: case 0x48E: case 0x490: case 0x495: case 0x496: case 0x499:
            case 0x49E: case 0x4A3: case 0x4A8: case 0x4A9: case 0x4AD: case 0x4B2: case 0x4B6: case 0x4BB:
            case 0x4BF: case 0x4C6: case 0x4C9: case 0x4CB: case 0x4CF: case 0x4D3: case 0x4D4: case 0x4D6:
            case 0x4E1: case 0x4E2: case 0x4E6: case 0x4EA: case 0x4EC: case 0x4ED: case 0x4EF: case 0x4F0:
            case 0x4F1: case 0x4F3: case 0x4FA: case 0x4FE: case 0x502: case 0x503: case 0x509: case 0x50F:
            case 0x510: case 0x511: case 0x517: case 0x519: case 0x51D: case 0x51F: case 0x520: case 0x521:
            case 0x523: case 0x525: case 0x527:
                return true;
            default:
                return false;
        }
    }
}

#endif
