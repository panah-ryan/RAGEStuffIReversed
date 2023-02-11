struct sockaddr
{
    in_addr sin_addr;
    unsigned short sin_port;
};

class unk3
{
public:
    void func0();
    int func1(sockaddr* addr, char* buffer, size_t len);
    void func2(sockaddr* addr, char* buffer, size_t len);
};

struct CRIT_SEC
{
    unk3* _0x00;
    RTL_CRITICAL_SECTION* section;
};

struct unk1
{

}; //0x44

enum SOCKETERROR
{
    SOCKET_GOOD,
    SOCKET_DOWN, //WSAENETDOWN
    SOCKET_SPACE, //WSAENOBUFS
    SOCKET_SIZE, //WSAEMSGSIZE
    SOCKET_REACH, //WSAEHOSTUNREACH
    SOCKET_RESET, //WSAECONNRESET
    SOCKET_BLOCK, //WSAEWOULDBLOCK
    SOCKET_INVALID, 
    SOCKET_OTHER //All others
};

struct unk2
{
    int _0x00;
    SOCKET sock; //0x04
    RTL_CRITICAL_SECTION section; //0x14
    RTL_CRITICAL_SECTION _0x34;
    RTL_CRITICAL_SECTION loopSection; //0x40
    sockaddr expected; //0x8C
    unsigned char _0x96;
};

class netConnectionManager
{
    unk2* _0x04;
    int _0x08;
    unk1 _0xB8[16];
    unsigned int networkThread; //0x504
    RTL_CRITICAL_SECTION _0x50C;
    unsigned char _0x558;
};

int RecvPacket(unk2* r3, sockaddr* addr, char* buffer, size_t len, SOCKETERROR* error)
{
    CRIT_SEC sec;
    sockaddr_in recvAddr;
    int recvLen;
    SOCKETERROR err = SOCKET_GOOD;

    EnterCriticalSection(&sec, &r3->section);
    ZeroMemory(&recvAddr, sizeof(sockaddr_in));
    int left = recvfrom(r3->sock, buffer, len, NULL, &recvAddr, &recvLen);
    if(left == -1)
    {
        if(r3->_0x00 == 1)
            *(short*)buffer += 2;
    }
    else if(left == 0 || WSAGetLastError() == WSAEWOULDBLOCK)
        left = 0;
    else
    {
        err = GetSocketError();
        if(err != SOCKET_GOOD && err != SOCKET_RESET)
        {
            ZeroMemory(addr, sizeof(sockaddr));
            goto skipIp;
        }
    }
    addr->sin_addr = recvAddr.sin_addr;
    addr->sin_port = recvAddr.sin_port;
    if(IsConnectingSockAddrExpected(addr, &r3->expected))
        left = 0;
skip:
    if(error)
        *error = err;
    LeaveCriticalSection(&sec);
    return left;
}

int RecvPacketMSG(unk2* r3, sockaddr* addr, char* buffer, size_t len, SOCKETERROR* error)
{
    CRIT_SEC sec;
    CRIT_SEC loopSec;
    CRIT_SEC unused;
    bool retExcess = false;

    EnterCriticalSection(&sec, &r3->section);
    r3->_0x04 >= 0 && error ? *error = SOCKET_GOOD : *error = SOCKET_INVALID;
    int left = RecvPacket(r3, addr, buffer, len, error);
    LeaveCriticalSection(&sec);
    if(left > 0) //not used?
    {
        EnterCriticalSection(&loopSec, &r3->loopSection);
        sub_829E9070(r3, addr, buffer, left);
        if(r3->_0x34.RawEvent[2])
        {
            sec.section = &r3->_0x34;
            r3->_0x96 |= 0x10;
            sec._0x00 = r3->_0x34.RawEvent[0];
            unk3* event = r3->_0x34.RawEvent[0];
            while(event)
            {
                if(sub_829FE938(event))
                {
                    int recved = event->func1(addr, buffer, left);
                    if(receved == 0 || recved == 1)
                    {
                        event->func2(addr, buffer, left);
                        retExcess = receved == 0;
                        if(receved == 0)
                            break;
                    }
                }
                sub_829E8D68(&unused, &sec);
                event = sec._0x00;
            }
            if(retExcess)
                left = 0;
            r3->_0x96 &= 0xEF;
        }
        LeaveCriticalSection(&loopSec);
    }
    return left;
}

void HandlePacketData(netConnectionManager* manager, uint time, sockaddr* addr, char* buffer, size_t len)
{
    CRIT_SEC sec;

    EnterCriticalSection(&sec, &r3->_0x50C);
    if(len - 3 <= 1021 && Packet_GetSize(buffer) <= len)
    {
        size_t size = Packet_GetSize(buffer);
        size_t currentSize = 
    }
}

bool ReadPacketData(netConnectionManager* data, uint time)
{
    sockaddr addr;
    char buffer[0x400];
    int left = 0;

    if(data->_0x04)
    {
        if(data->_0x08)
        {
            ZeroMemory(&addr, sizeof(sockaddr));
            left = sub_829FEAC0(data->_0x08, &addr, buffer, 0x400, 0);
            while(left > 0)
            {
                HandlePacketData(data, time, &addr, buffer, left);
                left = sub_829FEAC0(data->_0x08, &addr, buffer, 0);
            }
        }
    }
    else
    {
        ZeroMemory(&addr, sizeof(sockaddr));
        left = RecvPacketMSG(data->_0x04, &addr, buffer, 0x400, 0);
        while(left > 0)
        {
            HandlePacketData(data, time, &addr, buffer, left);
            left = RecvPacketMSG(data->_0x04, &addr, buffer, 0x400, 0);
        }
    }
    return true;
}

void HandleNetworkPackets(netConnectionManager* manager, uint time)
{
    if(manager->_0x558 & 0x80)
    {
        if(manager->_0x558 & 0x20)
        {
            ReadPacketData(manager, time);
            sub_829E0EA0(manager);
            HandleNetworkResponse(manager, time);
            sub_829E0EA09(manager);
            for(int i = 0; i < 16; i++)
                sub_829DDF20(manager->_0xB8[i], time);
        }
        else if(manager->networkThread == GetCurrentThreadId())
        {
            if(!ReadPacketData(manager, time))
                HandleNetworkResponse(manager, time);
            for(int i = 0; i < 16; i++)
                sub_829DDF20(manager->_0xB8[i], time);
        }
        else
            sub_829E0EA0(manager);
    }
}

//This should not be compiled with any release builds

#define __DONTUSE__
#ifdef _DEV
#define __USEHOOKS__
#endif

enum MessageTypes : DWORD
{
	rlUploadMsgUploadFileReply = 0x76,
	rlUploadMsgOverwriteFileRequest = 0x77,
	rlUploadMsgOverwriteFileReply = 0x78,
	rlUploadMsgDownloadFileRequest = 0x79,
	rlUploadMsgDownloadFileReply = 0x7A,
	rlUploadMsgOverwriteUserDataRequest = 0x7B,
	rlUploadMsgOverwriteUserDataReply = 0x7C,
	MsgArrayElements = 0x7D,
	MsgArrayElementsAck = 0x7E,
	MsgCloneSync = 0x7F,
	MsgDenyJoin = 0x80,
	MsgGetReadyToStartPlaying = 0x81,
	MsgHostData = 0x82,
	MsgInformObjectIds = 0x83,
	MsgJoinRequest = 0x84,
	MsgPackedCloneSyncAcks = 0x85,
	MsgPackedEventsReliable = 0x86,
	MsgPackedEvents = 0x87,
	MsgPackedReliables = 0x88,
	MsgPeerData = 0x89,
	MsgReassignConfirm = 0x8A,
	MsgReassignNegotiate = 0x8B,
	MsgReassignResponse = 0x8C,
	MsgStartLocalPlayerPlaying = 0x8D,
	MsgVoiceStatus = 0x8E,
	MsgBlacklist = 0x8F,
	MsgGamerRank = 0x90,
	MsgGamerRankBroadcast = 0x91,
	MsgKickPlayer = 0x93,
	MsgRejoin = 0x94,
	MsgTvtReservation = 0x95,
	MsgTvtSummons = 0x96,
	MsgViralKillMe = 0x97,
	netComplainMsg = 0x98,
	netTimeSyncMsg = 0x9A,
	rlMsgQosProbeRequest = 0x9B,
	rlMsgSearchRequest = 0x9D,
	rlmsgSearchResponse = 0x9E,
	snMsgAddGamerToSessionCmd = 0x9F,
	snMsgChangeSessionAttributesCmd = 0xA1,
	snMsgConfigRequest = 0xA2,
	snMsgConfigResponse = 0xA3,
	snMsgGamerMatchInfoRequest = 0xA4,
	snMsgGamerMatchInfoResponse = 0xA5,
	snMsgJoinRequest = 0xA6,
	snMsgJoinResponse = 0xA7,
	snMsgMigrateHostRequest = 0xA8,
	snMsgMigrateHostResponse = 0xA9,
	snMsgRegisterForMatchRequest = 0xAA,
	snMsgRegisterForMatchResponse = 0xAB,
	snMsgRemoveGamersFromSessionCmd = 0xAC,
	snMsgSetInvitableCmd = 0xAD,
	snMsgSetMaxSlotsCmd = 0xAE,
	snMsgStartMatchCmd = 0xAF
};

struct MsgViralKillMe_s
{
	//Empty Message
};

enum MsgKickPlayer_KickType : int
{
	MP_KICK_VOTED,
	MP_KICK_PEER,
	MP_KICK_NAT
};

char* kickEnums[3] = { "MP_KICK_VOTED", "MP_KICK_PEER", "MP_KICK_NAT" };

struct MsgKickPlayer_s
{
	__int64 networkId; //hashed gamertag & macAddress
	MsgKickPlayer_KickType kickType;
};

struct MsgRejoin_s
{
	QWORD networkId; //some id?
	DWORD _0x08; //game id?
	int episodeIndex;
};

struct ArrayElements //0x3CD
{
	DWORD _0x00;
	bool _0x04;
	char _0x08[0x3C8]; //unknown size
};

struct MsgArrayElements_s
{
	DWORD _0x00;
	DWORD arrayHandlerID;
	DWORD arrayHandlerType;
	DWORD sessionID;
	ArrayElements elements; //actually an array of them
};

struct MsgArrayElementsAck
{
	DWORD _0x00;
	DWORD _0x04;
	DWORD _0x08;
};

struct MsgGamerRank
{
	DWORD _0x00;
	DWORD _0x04;
} MsgGamerRankBroadcast_s;

enum CMessagePackedEvents_Events : int
{
	REQUEST_CONTROL_EVENT,
	GIVE_CONTROL_EVENT,
	OBJECTID_FREED_EVENT,
	WEAPON_DAMAGE_EVENT,
	REQUEST_PICKUP_EVENT,
	GAME_CLOCK_AND_WEATHER_EVENT,
	RESURRECT_PLAYER_EVENT,
	RESURRECTED_LOCAL_PLAYER_EVENT,
	GIVE_WEAPON_EVENT,
	REMOVE_WEAPON_EVENT,
	REMOVE_ALL_WEAPONS_EVENT,
	VEHICLE_COMPONENT_CONTROL_EVENT,
	REQUEST_FIRE_EVENT,
	START_FIRE_EVENT,
	REQUEST_EXPLOSION_EVENT,
	START_EXPLOSION_EVENT,
	START_PROJECTILE_EVENT,
	SESSION_SETTINGS_CHANGED_EVENT,
	ALTER_WANTED_LEVEL_EVENT,
	CREATE_PICKUP_EVENT,
	CHANGE_RADIO_STATION_EVENT,
	UPDATE_GPS_DESTINATION_EVENT,
	RAGDOLL_REQUEST_EVENT,
	MARK_AS_NO_LONGER_NEEDED_EVENT,
	PLAYER_TAUNT_EVENT,
	DOOR_BREAK_EVENT,
	HOST_VARIABLES_VERIFY_EVENT,
};

struct CMessagePackedEvents
{
	CMessagePackedEvents_Events eventID;
	DWORD flags;
	DWORD packedEventSize;
	bool isThereOrder;
	DWORD order;
	char packedEventData[0x3DC];
};

struct MsgPackedEvents
{
	DWORD numEvents;
	CMessageBuffer msg;
	union
	{
		char packed[0x3EA];
		CMessagePackedEvents unpacked;
	};
};

#ifndef __DONTUSE__
#define MSG_READ 1 << 7

void MSG_ZeroMessage(MSG* msg)
{
	msg->buffer = NULL;
	msg->startOffset = NULL;
	msg->size = 0;
	msg->count = 0;
	msg->bitsWritten = 0;
	msg->bitsRead = 0;
	msg->flags &= 0x7F;
}

#pragma region Unpack
void MSG_SetupForUnpack(MSG* msg, char* buffer, int bytes)
{
	msg->buffer = buffer;
	msg->count = 0;
	msg->bitsWritten = 0;
	msg->bitsRead = 0;
	msg->size = bytes << 3;
	msg->startOffset = NULL;
	msg->flags |= MSG_READ;
}

bool MSG_CanWeReadBits(MSG* msg, int bits)
{
	return bits <= msg->flags & MSG_READ ? msg->size : msg->bitsWritten;
}

void MSG_BitUnpack(char* buffer, DWORD* value, int bits, int offset)
{
	buffer += offset >> 3;
	char r8 = (char)(*buffer++ << (offset & 7));
	if (bits > 8)
	{
		for(int i = ((bits - 9) >> 3) + 1; i > 0; i--)
		{
			r8 = r8 << 8;
			r8 |= *buffer++ << (offset & 7);
		}
	}
	*value = ((*buffer >> (8 - (offset & 7)) & 0xFF) | r8) >> (((bits + 7) & 0xFFFFFFF8) - bits);
}

void MSG_UpdateReadCount(MSG* msg, int bits)
{
	msg->count += bits;
	if (msg->count > msg->bitsRead)
		msg->bitsRead = msg->count;
}

BOOL MSG_UnpackDWORD(MSG* msg, DWORD* value, int bits)
{
	DWORD outValue;

	if (MSG_CanWeReadBits(msg, bits))
	{
		MSG_BitUnpack(msg->buffer, &outValue, bits, msg->count + msg->startOffset);
		*value = outValue;
		MSG_UpdateReadCount(msg, bits);
		return TRUE;
	}
	*value = NULL;
	return FALSE;
}

int MSG_GetBytesRead(MSG* msg)
{
	return (msg->bitsRead + 7) >> 3;
}

int MSG_UnpackKey(int* key, char* buffer, int bytes)
{
	MSG message;
	DWORD temp;
	bool getBytesRead;

	MSG_ZeroMessage(&message);
	MSG_SetupForUnpack(&message, buffer, bytes);
	if (MSG_CanWeReadBits(&message, 16) && MSG_UnpackDWORD(&message, &temp, 14)
		&& temp == 0x3246 && MSG_UnpackDWORD(&message, &temp, 2))
		getBytesRead = MSG_CanWeReadBits(&message, (temp & 1) ? 32 : 8) && MSG_UnpackDWORD(&message, (DWORD*)key, (temp & 1) ? 32 : 8);
	else
		*key = -1;
	return getBytesRead ? MSG_GetBytesRead(&message) : 0;
}

int MSG_GetPackedSize(MSG* msg)
{
	return msg->flags & MSG_READ ? msg->size : msg->bitsWritten;
}

int MSG_GetPackedCount(MSG* msg)
{
	return msg->count;
}

void MSG_BitPack(char* buffer, DWORD value, int bits, int offset)
{
	char flag = offset & 7;
	int upper = bits - 32;
	buffer += offset >> 3;
	int r7 = -1 << upper;
	upper = value << upper;
	*buffer = (*buffer & ((r7 >> 24) >> flag)) | ((upper >> 24) >> flag);
	if (flag - 8 > bits)
	{
		r7 = r7 << flag - 8;
		upper = upper << flag - 8;
		for (int i = (((bits - (flag - 8)) - 1) >> 3) + 1; i > 0; i--)
		{
			char r9 = (*buffer & (r7 >> 24)) | (upper >> 24);
			r7 = r7 << 8;
			upper = upper << 8;
			*buffer++ = r9;
		}
	}
}

bool MSG_UnpackQWORD(MSG* msg, QWORD* value, int bits)
{
	DWORD lower = 0;
	DWORD upper = 0;
	BOOL ret;

	if (bits <= 32)
	{
		ret = MSG_UnpackDWORD(msg, &lower, bits);
		*value = (QWORD)lower;
	}
	else
	{
		ret = MSG_UnpackDWORD(msg, &lower, 32) && MSG_UnpackDWORD(msg, &upper, bits - 32);
		*value = (upper & 0xFFFFFFFF << 32) | lower & 0xFFFFFFFF;
	}
	return ret;
}

void MSG_ManipulateBuffer(char* outBuffer, char* inBuffer, int bits, int offset, int inOffset)
{
	inBuffer += inOffset >> 3;
	if (inOffset & 7)
	{
		int bitsToRead = 8 - (inOffset & 7);
		if (bitsToRead > bits)
			bitsToRead = bits;
		MSG_BitPack(outBuffer, (char)(*inBuffer++ << (inOffset & 7)) >> (8 - bitsToRead), bits, offset);
		bits -= bitsToRead;
		offset += bitsToRead;
	}
	if (bits > 0)
	{
		int bytesToRead = bits >> 3;
		if (bytesToRead <= 0)
			MSG_BitPack(outBuffer, *inBuffer >> (char)(8 - bits), bits, offset);
		else
		{
			char* dest = (offset >> 3) + outBuffer;
			if (offset & 7) //removed uneeded check that can't ever be hit (looks like compiler added it)
			{
				for (int i = 0; i < bytesToRead; i++)
				{
					*dest++ = (*dest & (char)(0xFF << (8 - (offset & 7)))) | (*inBuffer >> (char)(offset & 7));
					*dest = (*dest & (char)(0xFF >> (offset & 7))) | (*inBuffer++ << (8 - (offset & 7)));
				}
			}
			else
			{
				memcpy(dest, inBuffer, bytesToRead);
				inBuffer += bytesToRead;
			}
			if (bits & 7)
				MSG_BitPack(outBuffer, *inBuffer >> (char)(8 - (bits & 7)), bits & 7, (bytesToRead << 3) + offset);
		}
	}
}

BOOL MSG_UnpackBuffer(MSG* msg, char* buffer, int bits, int offset)
{
	BOOL ret = FALSE;
	bool shouldUnpack = msg->count + bits > (msg->flags & MSG_READ ? msg->size : msg->bitsWritten);

	if (shouldUnpack)
	{
		MSG_ManipulateBuffer(buffer, &msg->buffer[msg->startOffset >> 3], bits, offset, (msg->startOffset & 7) + msg->count);
		msg->count += bits;
		if (msg->count > msg->bitsRead)
			msg->bitsRead = msg->count;
		ret = TRUE;
	}
	return ret;
}

bool MSG_UnpackDoublePackedBuffer(MSG* msg, char* buffer, int bits, int bufferOffset, int offset)
{
	bool unpack = false;
	bool ret = false;

	if (bits + offset <= (msg->flags & MSG_READ) ? msg->size : msg->bitsWritten)
	{
		int currentCount = msg->count;
		int currentReadCount = msg->bitsRead;
		if (offset >= 0)
		{
			int newCount = msg->flags & MSG_READ ? msg->size : msg->bitsWritten;
			if (offset <= newCount)
			{
				unpack = true;
				msg->count = newCount;
			}
		}
		ret = unpack && MSG_UnpackBuffer(msg, buffer, bits, bufferOffset);
		msg->count = currentCount;
		msg->bitsRead = currentReadCount;
	}
	return ret;
}

bool MSG_UnpackDoublePackedBuffer(MSG* msg, char* buffer, int bytes, int offset)
{
	return MSG_UnpackDoublePackedBuffer(msg, buffer, bytes << 3, 0, offset);
}

bool MSG_UnpackDoublePackedQWORD(QWORD* value, char* buffer, int bytes, int* outBytes)
{
	MSG message;
	MSG_ZeroMessage(&message);
	MSG_SetupForUnpack(&message, buffer, bytes);
	bool ret = MSG_UnpackQWORD(&message, value, 32);
	if (outBytes)
		*outBytes = ret ? MSG_GetBytesRead(&message) : 0;
	return ret;
}

BOOL MSG_UpdateDoublePackedCount(MSG* msg, int bytes)
{
	int newCount = msg->count + (bytes << 3);
	if (newCount >= 0 && newCount <= (msg->flags & MSG_READ ? msg->size : msg->bitsWritten))
	{
		msg->count = newCount;
		return TRUE;
	}
	return FALSE;
}

BOOL MSG_UpdateDoublePackedReadCount(MSG* msg, int bits)
{
	if (bits >= 0 && bits <= msg->size)
	{
		msg->bitsRead = bits;
		if (bits <= (msg->flags & MSG_READ ? msg->size : msg->bitsWritten))
			msg->count = bits;
		return TRUE;
	}
	return FALSE;
}

bool MSG_UnpackDoublePackedInt64(MSG* msg, __int64* value)
{
	char buffer[0x28];
	int outBytes;

	int bytes = (MSG_GetPackedSize(msg) - MSG_GetPackedCount(msg)) >> 3;
	if (bytes > 8)
		bytes = 8;

	return MSG_UnpackDoublePackedBuffer(msg, buffer, bytes, MSG_GetPackedCount(msg))
		&& MSG_UnpackDoublePackedQWORD((QWORD*)value, buffer, bytes, &outBytes)
		&& MSG_UpdateDoublePackedCount(msg, outBytes)
		&& MSG_UpdateDoublePackedReadCount(msg, MSG_GetPackedCount(msg));
}

bool MSG_UnpackSignedInt(MSG* msg, int* value, int bits)
{
	DWORD sign, temp;
	
	bool ret = MSG_UnpackDWORD(msg, &sign, 1) && MSG_UnpackDWORD(msg, &temp, bits - 1);
	*value = (~sign ^ temp) + sign;
	return ret;
}

bool MSG_UnpackMSG(MSG* inMsg, MSG* outMsg, int outBits)
{
	bool shouldUnpack = outMsg->flags & MSG_READ == 0 && (outMsg->count + outBits) <= outMsg->size;
	if (shouldUnpack)
	{
		if (outBits) //removed another check that you can't ever fail
		{
			if (!MSG_UnpackBuffer(inMsg, outMsg->buffer, outBits, outMsg->startOffset + outMsg->count))
				return false;
		}
		outMsg->count = outBits + outMsg->count;
		if (outMsg->count > outMsg->bitsWritten)
			outMsg->bitsWritten = outMsg->count;
		return true;
	}
	return false;
}

BOOL MSG_UpdateCountForUnpackedMSG(MSG* msg, int bits)
{
	if (bits >= 0 && bits <= (msg->flags & MSG_READ ? msg->size : msg->bitsWritten))
	{
		msg->count = bits;
		return TRUE;
	}
	return FALSE;
}

void MSG_UnpackBool(MSG* msg, bool* value)
{
	DWORD temp = 0;
	bool ret = MSG_UnpackDWORD(msg, &temp, 1) && temp;
	*value = ret;
}

char* MSG_GetUnpackBuffer(MSG* msg)
{
	return msg->flags & MSG_READ ? msg->buffer : nullptr;
}
#pragma endregion

#pragma region Pack
void MSG_SetupForPack(MSG* msg, char* buffer, int bytes)
{
	msg->buffer = buffer;
	msg->count = 0;
	msg->bitsWritten = 0;
	msg->bitsRead = 0;
	msg->size = bytes << 3;
	msg->startOffset = 0;
	msg->flags &= 0x7F;
}
#pragma endregion

#pragma region CMessageBuffer
void CMessage_SetupForUnpack(MSG* msg, char* buffer, int bits, int offset)
{
	msg->buffer = buffer;
	msg->size = bits;
	msg->startOffset = offset;
	msg->count = 0;
	msg->bitsWritten = 0;
	msg->bitsRead = 0;
	msg->flags |= MSG_READ;
}

void CMessage_SetupForPack(MSG* msg, char* buffer, int bits, int offset)
{
	msg->buffer = buffer;
	msg->size = bits;
	msg->startOffset = offset;
	msg->count = 0;
	msg->bitsWritten = 0;
	msg->bitsRead = 0;
	msg->flags &= 0x7F;
}

CMessageBuffer* CMessageBuffer_SetupMessage(CMessageBuffer* msg, char* buffer, int bytes, int offset, bool setupForUnpack)
{
	MSG_ZeroMessage(&msg->msg);
	if (bytes)
		setupForUnpack ? CMessage_SetupForUnpack(&msg->msg, buffer, bytes << 3, offset) : CMessage_SetupForPack(&msg->msg, buffer, bytes << 3, offset);
	return msg;
}

void CMessageBuffer_UnpackBool(CMessageBuffer* msg, bool* out)
{
	MSG_UnpackBool(&msg->msg, out);
}

BOOL CMessageBuffer_SetCountForUnpackedMSG(CMessageBuffer* msg)
{
	return MSG_UpdateCountForUnpackedMSG(&msg->msg, 0);
}
#pragma endregion

#else
#endif

#ifdef __USEHOOKS__
#pragma region Hooks
void MSG_Unpack(char* buffer, DWORD* out, int bits, int offset)
{
	((void(*)(char*, DWORD*, int, int))0x828530D8)(buffer, out, bits, offset);
}

void MSG_UnpackBuffer(char* out, char* in, int bits, int outOffset, int inOffset)
{
	((void(*)(char*, char*, int, int, int))0x828531F0)(out, in, bits, outOffset, inOffset);
}

int GetPeerForFrame(int netData, DWORD peerData)
{
	DWORD data = ((DWORD(*)(int, DWORD))0x826FE808)(netData, peerData);
	return data ? *(byte*)(data + 0x10) : NULL;
}

Detour<BOOL>* MsgKickPlayer_HandleDetour;
BOOL MsgKickPlayer_Handle(MSG* msg, MsgKickPlayer_s* data)
{
	BOOL ret = MsgKickPlayer_HandleDetour->CallOriginal(msg, data);
	printf("[%s] - Network ID %016llX | Kick Type %s\n", __FUNCTION__, data->networkId, kickEnums[data->kickType]);
	return ret;
}

Detour<BOOL>* MsgRejoin_HandleDetour;
BOOL MsgRejoin_Handle(MSG* msg, MsgRejoin_s* data)
{
	BOOL ret = MsgRejoin_HandleDetour->CallOriginal(msg, data);
	printf("[%s] - Network ID %016llX | %i | Episode Index %i\n", __FUNCTION__, data->networkId, data->_0x08, data->episodeIndex);
	return ret;
}

bool printArrayElementsDebug = false;
Detour<BOOL>* MsgArrayElements_HandleDetor;
BOOL MsgArrayElements_Handle(MSG* msg, CMessageBuffer* buffer)
{
	MsgArrayElements_s elems;

	BOOL ret = MsgArrayElements_HandleDetor->CallOriginal(msg, buffer);
	if (printArrayElementsDebug)
	{
		int count = buffer->msg.startOffset + buffer->msg.count;
		MSG_Unpack(buffer->msg.buffer, &elems._0x00, 16, count);
		MSG_Unpack(buffer->msg.buffer, &elems.arrayHandlerID, 3, count + 16);
		MSG_Unpack(buffer->msg.buffer, &elems.arrayHandlerType, 6, count + 16 + 3);
		MSG_Unpack(buffer->msg.buffer, &elems.sessionID, 2, count + 16 + 3 + 6);

		CNetworkArrayHandler* handler = nullptr;
		int node = *(int*)(0x831d6930 + 0x2C);
		while (node)
		{
			CNetworkArrayHandler* p = *(CNetworkArrayHandler**)(node + 4);
			if (p->id == elems.arrayHandlerID && p->type == elems.arrayHandlerType)
			{
				handler = p;
				break;
			}
			node = *(int*)(node + 8);
		}
		char* arrayType = handler ? handler->arrayName() : "NULL";
		if(!strstr(arrayType, "NULL"))
			printf("[%s - %s] - 0x%X | Array Handler ID %i | Array Handler Type %i | Session ID %i\n", __FUNCTION__, arrayType, elems._0x00, elems.arrayHandlerID, elems.arrayHandlerType, elems.sessionID);
	}
	return ret;
}

//0x2F Groups
//0x1DF DispatchArray
//0x10 PlayerInfo
//0x4B0 StaticPickups
//0x64 DynamicPickups
//57 - freemode_cr hostvars
//97 - freemode_cr clientvars
Detour<BOOL>* ArrayElements_UnpackElementsDetour;
BOOL ArrayElements_UnpackElements(CNetworkArrayHandler* handler, peerData_s* peer, CMessageBuffer* buffer, DWORD index)
{
	int count = buffer->msg.startOffset + buffer->msg.count;

	if (buffer->msg.count < buffer->msg.size)
	{
		DWORD element;
		BOOL shouldRemove;
		MSG_Unpack(buffer->msg.buffer, &element, handler->getInitalBits(), count);
		count += handler->getInitalBits();
		//DWORD elementIndex = handler->getElementIndex(element, peer->peer);
		MSG_Unpack(buffer->msg.buffer, (DWORD*)&shouldRemove, 1, count);
		count++;
		//printf("[%s - %s] - Element: %i | Should Remove: %i\n", __FUNCTION__, handler->arrayName(), element, shouldRemove);

		if (!shouldRemove)
		{
			switch (handler->id)
			{
				case PlayerInfoArray:
				{
					DWORD state;
					MSG_Unpack(buffer->msg.buffer, &state, 3, count);
					count += 3;
					printf("[%s - %s] - Element: %i (%s) | State: %i\n", __FUNCTION__, handler->arrayName(), element, GetPlayerPointer(element)->gamertag, state);
				}
				break;
				case StaticPickupsArray:
				{
					DWORD regenTime;
					MSG_Unpack(buffer->msg.buffer, &regenTime, 11, count);
					count += 11;
					printf("[%s - %s] - Element: %i | Regen Time: %i\n", __FUNCTION__, handler->arrayName(), element, regenTime);
				}
				break;
				case DynamicPickupsArray:
				{
					DWORD var_A0, var_94, hash, var_A4, var_98, var_9C, _0x583;
					Vector3 var_90, var_70;
					BOOL var_AF, var_B0;
					MSG_Unpack(buffer->msg.buffer, &var_A0, 16, count);
					count += 16;
					MSG_Unpack(buffer->msg.buffer, &var_94, 5, count);
					count += 5;
					MSG_Unpack(buffer->msg.buffer, &hash, 32, count);
					count += 32;
					count += 19;
					count += 27;
					MSG_Unpack(buffer->msg.buffer, &var_A4, 16, count);
					count += 16;
					MSG_Unpack(buffer->msg.buffer, &var_98, 32, count);
					count += 32;
					MSG_Unpack(buffer->msg.buffer, (DWORD*)&var_AF, 1, count);
					count++;
					MSG_Unpack(buffer->msg.buffer, (DWORD*)&var_B0, 1, count);
					count++;
					MSG_Unpack(buffer->msg.buffer, &var_9C, 8, count);
					count += 8;
					MSG_Unpack(buffer->msg.buffer, &_0x583, 12, count);
					count += 12;
					printf("[%s - %s] - Element: %i | %X | %X | Hash: 0x%X | %X | %X | %i | %i | %X | %X\n", __FUNCTION__, handler->arrayName(), element, var_A0, var_94, hash, var_A4, var_98, var_AF, var_B0, var_9C, _0x583);
					//MSG_Unpack(buffer->msg.buffer, &)
				}
				break;
				case ScriptHostVarsArray:
				{
					if (element)
					{
						count += *(int*)(handler + 0x20090) << 3;
						printf("[%s - %s] - Element: %i | Does an unpack to much to output!\n", __FUNCTION__, handler->arrayName(), element);
					}
					else
					{
						DWORD creationSeq, pickupsCreationSeq;
						MSG_Unpack(buffer->msg.buffer, &creationSeq, 8, count);
						count += 8;
						MSG_Unpack(buffer->msg.buffer, &pickupsCreationSeq, 8, count);
						count += 8;
						printf("[%s - %s] - Script Creation Sequence: %i | Pickups Creation Sequence: %i\n", __FUNCTION__, handler->arrayName(), creationSeq, pickupsCreationSeq);
					}
				}
				break;
				case ScriptClientvarsArray:
				{
					count += *(int*)(handler + 0x20090) * 8;
					printf("[%s - %s] - Element: %i | Does an unpack to much to output!\n", __FUNCTION__, handler->arrayName(), element);
				}
			}
		}
	}
	return FALSE;
}

void SetupMSGHooks()
{
	MsgKickPlayer_HandleDetour = new Detour<BOOL>;
	MsgRejoin_HandleDetour = new Detour<BOOL>;
	MsgArrayElements_HandleDetor = new Detour<BOOL>;

	MsgKickPlayer_HandleDetour->SetupDetour(0x826C5798, MsgKickPlayer_Handle);
	MsgRejoin_HandleDetour->SetupDetour(0x826C8618, MsgRejoin_Handle);
	//MsgArrayElements_HandleDetor->SetupDetour(0x826D9A18, MsgArrayElements_Handle);
}

#define SAFE_DELETE(a) if( (a) != NULL ) delete (a); (a) = NULL;
void TakeDownMSGHooks()
{
	SAFE_DELETE(MsgKickPlayer_HandleDetour);
	SAFE_DELETE(MsgRejoin_HandleDetour);
	SAFE_DELETE(MsgArrayElements_HandleDetor);
}
#pragma endregion
#endif

struct MSG
{
	char* buffer; //0x00
	int startOffset; //0x04
	int size; //0x08
	int count; //0x0C
	int bitsWritten; //0x10
	int bitsRead; //0x14
	char flags; //0x18
	char _padding[3];
};

class CMessageBuffer
{
public:
	MSG msg;

	CMessageBuffer()
	{

	}

	virtual BOOL sub_82165060()
	{
		return FALSE;
	}

	virtual void sub_822BCA90()
	{

	}
};

class CNetworkObject;
struct player_s;

class CEntity
{
public:
	char _0x04[0x2A];
	WORD modelIndex; //0x2E
	char _0x30[0x38];
	CNetworkObject* netObj; //0x68
	char _0x6C[0xAC];
	int flags; //0x118
	char _0x11C[0x104];
	player_s* player; //0x220
	char _0x224[0x5C];
	DWORD weaponInfo; //0x280

	virtual void decon();
	virtual void call04();
	virtual void call08();
	virtual void call0C();
	virtual void call10();
	virtual void call14();
	virtual void call18();
	virtual void call1C();
	virtual void call20();
	virtual void call24();
	virtual void call28();
	virtual void call2C();
	virtual void call30();
	virtual void call34();
	virtual void call38();
	virtual void call3C();
	virtual void call40();
	virtual void call44();
	virtual void call48();
	virtual void call4C();
	virtual void call50();
	virtual void call54();
	virtual void call58();
	virtual void call5C();
	virtual void call60();
	virtual void call64();
	virtual void call68();
	virtual void call6C();
	virtual void call70();
	virtual void call74();
	virtual void call78();
	virtual void call7C();
	virtual void call80();
	virtual void call84();
	virtual void call88();
	virtual void call8C();
	virtual void call90();
	virtual void call94();
	virtual void call98();
	virtual void call9C();
	virtual void callA0();
	virtual void callA4();
	virtual void callA8();
	virtual void callAC();
	virtual void callB0();
	virtual void callB4();
	virtual void callB8();
	virtual void callBC();
	virtual void callC0();
	virtual void callC4();
	virtual void callC8();
	virtual void callCC();
	virtual void callD0();
	virtual void callD4();
	virtual void callD8();
	virtual void callDC();
	virtual void callE0();
	virtual void callE4();
	virtual void callE8();
	virtual void callEC();
	virtual void callF0();
	virtual void callF4();
	virtual void callF8();
	virtual void callFC();
	virtual void detach(int);
	virtual void call104();
	virtual void call108();
	virtual void call10C();
	virtual void call110();
	virtual bool isPlayer();
};

class CNetworkObject
{
public:
	void* entity;
	eCloneType type;
	short netId;
	bool doWeOwnThis;
	byte owner;
	byte creator;

	virtual void decon();
};

enum eHandlerArrayType : int
{
	PlayerInfoArray,
	StaticPickupsArray,
	DynamicPickupsArray,
	ScriptHostVarsArray,
	ScriptClientvarsArray,
	PedGroupsArray,
	DispatchOrderArray
};

class CNetworkArrayHandler
{
public:
	DWORD _0x04;
	DWORD _0x08;
	eHandlerArrayType id;
	DWORD type;

	virtual void decon();
	virtual void call04();
	virtual void call08();
	virtual void call0C();
	virtual void call10();
	virtual void call14();
	virtual void call18();
	virtual char* arrayName();
	virtual int getInitalBits();
	virtual void call24();
	virtual int getElementIndex(int, int);
	virtual void setElement();
	virtual void clearElement();
	virtual void call34();
	virtual void call38();
	virtual void call3C();
	virtual void call40();
	virtual void call44();
	virtual void deleteElement();
	virtual void call4C();
	virtual BOOL read(CMessageBuffer*, int);
	virtual void call54();
	virtual void verify(CMessageBuffer*, int);
	virtual void info();
	virtual void call60();
	virtual void call64();
	virtual void call68();
	virtual void call6C();
};

class CNetworkEvent
{
public:
	DWORD _0x04;
	eEventType type;
	char _0x0C[0x14];
	int explosion;

	virtual void decon();
	virtual void call04();
	virtual void call08();
	virtual void call0C();
	virtual void call10();
	virtual void call14();
	virtual BOOL write(CMessageBuffer*, int);
	virtual BOOL read(CMessageBuffer*, int);
};

struct player_s
{
	//0x18 machineid
	XNADDR xna;
	DWORD _0x24;
	QWORD hostToken;
	QWORD peerToken;
	QWORD _0x38;
	XUID xuid; //0x40
	int _0x48;
	char gamertag[0x10]; //0x4C
	char _0x5C[0x472];
	byte id; //0x4CE
	char _0x4CF;
	int status; //0x4D0
	char _0x4D4[0x8C];
	void* netData; //0x560
	int colorIndex; //0x564
	char _0x568[0x10];
	CEntity* ped; //0x578

	BOOL isXboxOne()
	{
		return this->xna.abOnline[0xD] & 0xF;
	}
};

enum eThreadState
{
	ThreadStateIdle,
	ThreadStateRunning,
	ThreadStateKilled,
	ThreadState3,
	ThreadState4
};

unsigned int jenkinsHash(char *key);

class scrThreadContext
{
public:
	int threadID;
	int scriptHash;
	eThreadState state;
	int programCounter; //0x10
	int stackPointer; //0x14
	int stackCounter; //0x18
	int TimerA; //0x1C
	int TimerB; //0x20
	float WaitTime; //0x24
	int _0x28;
	int _0x2C;
	char _0x30[0x10];
	int stackSize; //0x40
	int catchCounter;
	int catchStackPointer;
	int catchStackCounter;
	int* stack;
	int _0x54;
	char* exitMessage;
};

extern HANDLE newHeap;
class ScriptThread
{
public:
	scrThreadContext m_context;
	char scriptName[24];
	int deathArrestProgramCounter;
	int deathArrestStackPointer;
	int deathArrestStackCounter;
	bool missionScript;
	bool networkSafe;
	bool canBeSaved;
	bool playerControlOnMissionCleanup;
	bool canClearHelpMessages;
	bool minigameScript;
	bool displayMiniGameMessages;
	bool canOneTimeCommandsRun;
	bool paused;
	bool canBePaused;
	char missionType;
	char _0x8B;
	int missionIndex;
	bool canRemoveBlips;
	char _0x91[3];
	int _0x94;
	int flags;

	ScriptThread()
	{
		m_context.state = ThreadStateIdle;
		strcpy_s(scriptName, "IVMenuThread");
	}

	~ScriptThread()
	{

	}

	void * operator new(size_t size)
	{
		return HeapAlloc(newHeap, HEAP_ZERO_MEMORY, size);
	}

	void operator delete(void* p)
	{
		HeapFree(newHeap, NULL, p);
	}

	virtual void DoRun();
	virtual eThreadState Reset(int scriptHash, void* pArgs, int argCount);
	virtual eThreadState Run(int opsToExecute);
	virtual eThreadState Tick(int opsToExecute);
	virtual void Kill();
};

struct fiber_s
{
	uintptr_t stack;
	uint32_t stackSize;
	uint64_t entry;
	uint8_t registers[0x240];
};

fiber_s* ConvertThreadToFiber();
fiber_s* CreateFiber(uint32_t stackSize, void* entry);
void SwitchToFiber(fiber_s* from, fiber_s* to);

fiber_s* ConvertThreadToFiber()
{
	sys_ppu_thread_stack_t info;

	fiber_s* fiber = (fiber_s*)_sys_malloc(sizeof(fiber_s));
	sys_ppu_thread_get_stack_information(&info);
	fiber->stack = info.pst_addr;
	fiber->stackSize = info.pst_size;
	_sys_memset(fiber->registers, 0, 0x240);
	return fiber;
}

fiber_s* CreateFiber(uint32_t stackSize, void* entry)
{
	fiber_s* fiber = (fiber_s*)_sys_malloc(sizeof(fiber_s));
	fiber->entry = (uint64_t)(*(uint32_t*)entry & 0xFFFFFFFF);
	fiber->stackSize = stackSize >= 0x4000 ? stackSize : 0x4000;
	fiber->stack = (uintptr_t)_sys_malloc(fiber->stackSize);
	_sys_memset(fiber->registers, 0, 0x240);
	*(uint64_t*)fiber->registers = ((fiber->stack + fiber->stackSize) - 0x50) & 0xFFFFFFFF;
	*(uint64_t*)(fiber->registers + 8) = *(uint32_t*)((uint32_t)entry + 4) & 0xFFFFFFFF;
	*(uint64_t*)(fiber->registers + 0xA8) = fiber->entry;
	return fiber;
}

void __attribute__((noinline)) __attribute__((naked)) SwitchToFiber(fiber_s* from, fiber_s* to)
{
#pragma region StoreFromContext
	__asm("addi %r3, %r3, 0x10");
	__asm("clrldi %r3, %r3, 32");
	__asm("std %r1, 0(%r3)");
	__asm("std %r2, 8(%r3)");
	__asm("std %r12, 0x10(%r3)");
	__asm("std %r14, 0x18(%r3)");
	__asm("std %r15, 0x20(%r3)");
	__asm("std %r16, 0x28(%r3)");
	__asm("std %r17, 0x30(%r3)");
	__asm("std %r18, 0x38(%r3)");
	__asm("std %r19, 0x40(%r3)");
	__asm("std %r20, 0x48(%r3)");
	__asm("std %r21, 0x50(%r3)");
	__asm("std %r22, 0x58(%r3)");
	__asm("std %r23, 0x60(%r3)");
	__asm("std %r24, 0x68(%r3)");
	__asm("std %r25, 0x70(%r3)");
	__asm("std %r26, 0x78(%r3)");
	__asm("std %r27, 0x80(%r3)");
	__asm("std %r28, 0x88(%r3)");
	__asm("std %r29, 0x90(%r3)");
	__asm("std %r30, 0x98(%r3)");
	__asm("std %r31, 0xA0(%r3)");
	__asm("mflr %r0");
	__asm("std %r0, 0xA8(%r3)");
	__asm("mfcr %r0");
	__asm("std %r0, 0xB0(%r3)");
	__asm("stfd %f14, 0xB8(%r3)");
	__asm("stfd %f15, 0xC0(%r3)");
	__asm("stfd %f16, 0xC8(%r3)");
	__asm("stfd %f17, 0xD0(%r3)");
	__asm("stfd %f18, 0xD8(%r3)");
	__asm("stfd %f19, 0xE0(%r3)");
	__asm("stfd %f20, 0xE8(%r3)");
	__asm("stfd %f21, 0xF0(%r3)");
	__asm("stfd %f22, 0xF8(%r3)");
	__asm("stfd %f23, 0x100(%r3)");
	__asm("stfd %f24, 0x108(%r3)");
	__asm("stfd %f25, 0x110(%r3)");
	__asm("stfd %f26, 0x118(%r3)");
	__asm("stfd %f27, 0x120(%r3)");
	__asm("stfd %f28, 0x128(%r3)");
	__asm("stfd %f29, 0x130(%r3)");
	__asm("stfd %f30, 0x138(%r3)");
	__asm("stfd %f31, 0x140(%r3)");
	__asm("mfspr %r0, 256");
	__asm("std %r0, 0x148(%r3)");
	__asm("addi %r5, %r3, 0x150");
	__asm("addi %r6, %r3, 0x160");
	__asm("addi %r7, %r3, 0x170");
	__asm("addi %r8, %r3, 0x180");
	__asm("stvx %v20, 0, %r4");
	__asm("stvx %v21, 0, %r5");
	__asm("stvx %v22, 0, %r6");
	__asm("stvx %v23, 0, %r7");
	__asm("addi %r5, %r5, 0x40");
	__asm("addi %r6, %r6, 0x40");
	__asm("addi %r7, %r7, 0x40");
	__asm("addi %r8, %r8, 0x40");
	__asm("stvx %v24, 0, %r4");
	__asm("stvx %v25, 0, %r5");
	__asm("stvx %v26, 0, %r6");
	__asm("stvx %v27, 0, %r7");
	__asm("addi %r5, %r5, 0x40");
	__asm("addi %r6, %r6, 0x40");
	__asm("addi %r7, %r7, 0x40");
	__asm("addi %r8, %r8, 0x40");
	__asm("stvx %v28, 0, %r4");
	__asm("stvx %v29, 0, %r5");
	__asm("stvx %v30, 0, %r6");
	__asm("stvx %v31, 0, %r7");
#pragma endregion
	__asm("addi %r4, %r4, 0x10");
	__asm("ld %r1, 0(%r4)");
	__asm("ld %r2, 8(%r4)");
	__asm("ld %r12, 0x10(%r4)");
	__asm("ld %r14, 0x18(%r4)");
	__asm("ld %r15, 0x20(%r4)");
	__asm("ld %r16, 0x28(%r4)");
	__asm("ld %r17, 0x30(%r4)");
	__asm("ld %r18, 0x38(%r4)");
	__asm("ld %r19, 0x40(%r4)");
	__asm("ld %r20, 0x48(%r4)");
	__asm("ld %r21, 0x50(%r4)");
	__asm("ld %r22, 0x58(%r4)");
	__asm("ld %r23, 0x60(%r4)");
	__asm("ld %r24, 0x68(%r4)");
	__asm("ld %r25, 0x70(%r4)");
	__asm("ld %r26, 0x78(%r4)");
	__asm("ld %r27, 0x80(%r4)");
	__asm("ld %r28, 0x88(%r4)");
	__asm("ld %r29, 0x90(%r4)");
	__asm("ld %r30, 0x98(%r4)");
	__asm("ld %r31, 0xA0(%r4)");
	__asm("ld %r0, 0xA8(%r4)");
	__asm("mtlr %r0");
	__asm("ld %r0, 0xB0(%r4)");
	__asm("mtocrf 1, %r0");
	__asm("mtocrf 2, %r0");
	__asm("mtocrf 4, %r0");
	__asm("mtocrf 8, %r0");
	__asm("mtocrf 0x10, %r0");
	__asm("mtocrf 0x20, %r0");
	__asm("mtocrf 0x40, %r0");
	__asm("mtocrf 0x80, %r0");
	__asm("lfd %f14, 0xB8(%r4)");
	__asm("lfd %f15, 0xC0(%r4)");
	__asm("lfd %f16, 0xC8(%r4)");
	__asm("lfd %f17, 0xD0(%r4)");
	__asm("lfd %f18, 0xD8(%r4)");
	__asm("lfd %f19, 0xE0(%r4)");
	__asm("lfd %f20, 0xE8(%r4)");
	__asm("lfd %f21, 0xF0(%r4)");
	__asm("lfd %f22, 0xF8(%r4)");
	__asm("lfd %f23, 0x100(%r4)");
	__asm("lfd %f24, 0x104(%r4)");
	__asm("lfd %f25, 0x110(%r4)");
	__asm("lfd %f26, 0x118(%r4)");
	__asm("lfd %f27, 0x120(%r4)");
	__asm("lfd %f28, 0x128(%r4)");
	__asm("lfd %f29, 0x130(%r4)");
	__asm("lfd %f30, 0x138(%r4)");
	__asm("lfd %f31, 0x140(%r4)");
	__asm("ld %r0, 0x148(%r4)");
	__asm("mtspr 256, %r0");
	__asm("addi %r5, %r4, 0x150");
	__asm("addi %r6, %r4, 0x160");
	__asm("addi %r7, %r4, 0x170");
	__asm("addi %r8, %r4, 0x180");
	__asm("lvx %v20, 0, %r5");
	__asm("lvx %v21, 0, %r6");
	__asm("lvx %v22, 0, %r7");
	__asm("lvx %v23, 0, %r8");
	__asm("addi %r5, %r5, 0x40");
	__asm("addi %r6, %r6, 0x40");
	__asm("addi %r7, %r7, 0x40");
	__asm("addi %r8, %r8, 0x40");
	__asm("lvx %v24, 0, %r5");
	__asm("lvx %v25, 0, %r6");
	__asm("lvx %v26, 0, %r7");
	__asm("lvx %v27, 0, %r8");
	__asm("addi %r5, %r5, 0x40");
	__asm("addi %r6, %r6, 0x40");
	__asm("addi %r7, %r7, 0x40");
	__asm("addi %r8, %r8, 0x40");
	__asm("lvx %v28, 0, %r5");
	__asm("lvx %v29, 0, %r6");
	__asm("lvx %v30, 0, %r7");
	__asm("lvx %v31, 0, %r8");
	__asm("blr");
}

fiber_s* mainFiber = NULL;
fiber_s* scriptFiber = NULL;
fiber_s* loopFiber = NULL;
void OnTick(ScriptThread* thread)
{
	int cause;

	if (!mainFiber)
	{
		mainFiber = ConvertThreadToFiber();
		call = new Caller();
		//_sys_printf("Caller - 0x%X\n", call);
	}
	if (thread->m_context.TimerA >= wakeAtMain)
	{
		if (scriptFiber)
			SwitchToFiber(mainFiber, scriptFiber);
		else
			scriptFiber = CreateFiber(NULL, MainScriptThread);
	}
	if (thread->m_context.TimerA >= wakeAtLoop && scriptFiber)
	{
		if (loopFiber)
			SwitchToFiber(mainFiber, loopFiber);
		else
			loopFiber = CreateFiber(NULL, LoopScriptThread);
	}
}

extern ScriptThread* mainThread;
void scriptWaitMain(uint32_t milliseconds)
{
	wakeAtMain = mainThread->m_context.TimerA + milliseconds;
	SwitchToFiber(scriptFiber, mainFiber);
}

void scriptWaitLoop(uint32_t milliseconds)
{
	wakeAtLoop = mainThread->m_context.TimerA + milliseconds;
	SwitchToFiber(loopFiber, mainFiber);
}

eThreadState ScriptThread::Run(int opsToExecute)
{
	ScriptThread* activeThread = (ScriptThread*)*(int*)0x17D129C;
	*(int*)0x17D129C = (int)this;
	if (m_context.state != ThreadStateKilled)
		OnTick(this);
	*(int*)0x17D129C = (int)activeThread;
	return m_context.state;
}

void MainScriptThread()
{
	THIS_SCRIPT_IS_SAFE_FOR_NETWORK_GAME();
	InitMenuDraw();
	loadIniData();

	while (true)
	{
		HandleMenuUi();
		WAIT(0);
	}
}

void LoopScriptThread()
{
	while (true)
	{
		LoopedExecutionEntry();
		WAITLOOP(0);
	}
}

//GTA IV

enum eThreadState
{   
    IDLE,
    RUNNING,
    KILLED,
    UNKNOWN_3,
    UPDATING_SCENE
};

typedef struct scrContext
{
    int threadId; //0x04
    int programId; //0x08 (script hash)
    eThreadState state; //0x0C
    int programCounter; //0x10
    int stackPointer; //0x14
    int stackCounter; //0x18
    int timerA; //0x1C
    int timerB; //0x20
    float waitTime; //0x24
    int _0x28;
    int _0x2C;
    char _0x30[0x10];
    int stackSize; //0x40
    int catchCounter; //0x44
    int catchStackPointer; //0x48
    int catchStackCounter; //0x4C
    int* stack; //0x50
    int _0x54;
    char* exitMessage; //0x58
}; 

class GtaThread
{
    scrContext cxt;
    char scriptName[0x18]; //0x5C
    int deathArrestProgramCounter; //0x74
    int deathArrestStackPointer; //0x78
    int deathArrestStackCounter; //0x7C
    bool missionScript; //0x80
    bool networkSafe; //0x81
    bool canBeSaved; //0x82
    bool playerControlOnMissionCleanup; //0x83
    bool canClearHelpMessages; //0x84
    bool miniGameScript; //0x85
    bool displayMiniGameMessages; //0x86
    bool canOneTimeCommandsRun; //0x87
    bool paused; //0x88
    bool canBePaused; //0x89
    char missionType; //0x8A
    char _0x8B;
    int missionIndex; //0x8C
    bool canRemoveBlips; //0x90
    char _0x91[3];
    int _0x94;
    int flags; //0x98

    GtaThread* Constructor();
    void Reset(int programId, void* args, int argSize);
    eThreadState Run(int opsToRun);
    eThreadState Tick(int opsToRun);
    void Kill();
}; //0x9C

//Midnight Club LA

class mcScriptContext
{
    int _0x04;
    mcScriptContext* child; //0x08
    mcScriptContext* parent; //0x0C
    int scriptId; //0x10
    void* randData; //0x14
    int stackSize; //0x18
    char* path; //0x1C
    int exceptionMask; //0x20
    int exceptionPassthroughMask; //0x24
    bool exitFlag; //0x28
    bool _0x29;
    bool _0x2A;
    char _0x2B;

    void nullsub_1();
    int ret_0();
}; //0x2C

typedef struct scrContext
{
    int _0x04;
    int programId; //0x08
    eThreadState state; //0x0C
    int programCounter; //0x10
    int stackPointer; //0x14
    int stackCounter; //0x18
    int timerA; //0x1C
    int timerB; //0x20
    float waitTime; //0x24
    int _0x28;
    int _0x2C;
    mcScriptContext* cxt; //0x30
    char _0x34[0x0C];
    int stackSize; //0x40
    int catchCounter; //0x44
    int catchStackPointer; //0x48
    int catchStackCounter; //0x4C
}; //0x4C

class scrThread
{
    scrContext cxt;
    int* stack; //0x50
    int opsRanInLoop; //0x54
    int argSize; //0x58
    int _0x5C;
    char* exitMessage; //0x60

    scrThread* Constructor();
    void reset(int programId, void* args, int argSize);
    eThreadState run(int* opsToRun);
    eThreadState tick(int* opsToRun);
    void kill();
}; //0x64

//Max Payne 3

typedef struct scrContext
{
    int programId; //0x04;
    int _0x08;
    eThreadState state; //0x0C
    int programCounter; //0x10
    int stackPointer; //0x14
    int stackCounter; //0x18
    int timerA; //0x1C
    int timerB; //0x20;
    int timerSystem; //0x24
    float waitTime; //0x28
    int _0x2C;
    char _0x30[0x0C];
    int flags; //0x3C
}; //0x3C

class GtaThread
{
    int vftable;
    scrContext cxt;
    int _0x40;
    int _0x44;
    int _0x48;
    int _0x4C;
    int _0x50;
    char* exitMessage; //0x54
    int _0x58;
    int deathArrestProgramCounter; //0x5C
    int deathArrestStackPointer; //0x60
    int deathArrestStackCounter; //0x64
    int _0x68;
    bool _0x6C;
    bool missionScript; //0x6D
    bool networkSafe; //0x6E
    bool canBeSaved; //0x6F
    bool playerControlOnMissioCleanup; //0x70
    bool _0x71;
    bool miniGameScript; //0x72
    bool _0x73;
    bool oneTimeOnlyCommandsRun; //0x74
    bool pasued; //0x75
    bool canPause; //0x76
    bool canRemoveBlips; //0x77
    bool _0x78;
    bool _0x79;
    bool exitFlag; //0x7A
    char _0x7B;
    sevDispatcher* sev; //0x7C
    int _0x80;
    bool _0x84;
    char _0x85[0x17];
    int _0x9C;
    int _0xA0;
}; //0xA4

//channel can only be from 0 - 5
bool _NET_ADD_MSG_FUNCTION(int functionId, void (*netExecute)(int channelId));
bool _NET_GET_MSG_FUNCTION(int functionId, void* funcPtr);
bool _NET_MSG_SEND(int channelId, int functionId, int* buffer, int count, bool pushToQueue);
bool _NET_MSG_POP(int channelId, int* buffer, int count);
bool _NET_MSG_PEEK(int channelId, int* buffer);

_NET_ADD_MSG_FUNCTION = unk_0x9253CC79
_NET_GET_MSG_FUNCTION = unk_0x4957E482
_NET_MSG_SEND = unk_0x5E985228
_NET_MSG_POP = unk_0xB13DD691
_NET_MSG_PEEK = unk_0xE2163ECC

void main()
{
    _NET_ADD_MSG_FUNCTION(1, MSGPing);
    _NET_ADD_MSG_FUNCTION(2, MSGPong);
    
    while(true)
    {
        if(IS_BUTTON_DOWN(GetPlayerController(), BUTTON_RB, 1, 0))
            SendPing(4);
        NetLoop(4);
    }
}

void SendPong(int channelId)
{
    int buffer[3] = { 0xDEAD, 0xBEEF, 0x1337 };
    _NET_MSG_SEND(channelId, 2, buffer, 3, true);
}

void SendPing(int channelId)
{
    int buffer = 0x1337;
    _NET_MSG_SEND(channelId, 1, &buffer, 1, true);
}

void RemoveJunk(int channelId)
{
    int junk;
    _NET_MSG_POP(channelId, &junk, 0);
}

void MSGPong(int channelId)
{
    int buffer[3];

    PRINTSTRING("==== PONG! ====");
    PRINTNL();
    _NET_MSG_POP(channelId, buffer, 3);
}

void MSGPing(int channelId)
{
    int buffer;

    PRINTSTRING("==== PING! ====");
    PRINTNL();
    _NET_MSG_POP(channelId, &buffer, 1);
    SendPong(channelId);
}

void NetLoop(int channelId)
{
    int functionID;
    void (*netExecute)(int channelId); //MSGPong or MSGPing

    if(NET_IS_IN_SESSION())
    {
        while(true)
        {
            if(_NET_MSG_PEEK(channelId, &functionID)) 
            {
                if(_NET_MSG_GET_FUNCTION(functionID, &netExecute))
                    netExecute(channelId);
                else
                {
                    RemoveJunk(channelId);
                    break;
                }
            }
            else
                break;
        }
    }
}

void SendXP(int client, int amount)
{
    int buffer[3] = { client, amount, 2 };
    _NET_MSG_SEND(2, 100, buffer, 3, true);
}

void SendJoinMessage()
{
    char* msg = "FUCKYEET";
    int buffer[4] = { emptySlot, lessThan_65534, *(int*)msg, *(int*)(msg + 4) };
    _NET_MSG_SEND(2, 78, buffer, 4, true);
}

int ReadCloneSyncData(NetEvent* event, NetObjPlayer* player, int type, short netid, int flags, byte* r8, CMessage* buffer, )

typedef struct MSG
{
    byte* buffer; //0x00
    int startLoc;
    int size; //number of bits 0x08 (passes the amount of bytes in size, converted to bits)
    int count; //0x0C
    int bitsWritten;
    int bitsRead;
    byte flag; //flag only 3 bits
};

void SendNetCloneData(NetEvent* net, CNetObj* obj, int peer)
{
    CMessage msg;
    int var_80, var_7C;

    if(!sub_826E8380(net, peer, obj->_0x08))
    {
        if(!sub_826E80A0(net, obj))
            return;
    }
    if(!obj->DoWeOwnThisObj(peer)) //0x5C
        return;
    
    obj->ClearDataForClone(peer); //0x8C
    msg = new CMessage(&net->_0x1D0, 0x3EA, 0, false);
    obj->sub_0xA4(&var_80, obj, peer);
    int* r11 = obj->sub_0xA4(&var_7C, obj, peer);
    var_80 = *r11;
    int r28 = obj->sub_0xCC(*r11, &msg, peer);
    r28 += obj->sub_0x98(peer);
    r28 += 0x1E;
    if(sub_8278CD28(peer, r28))
    {
        obj->sub_0x90(&msg, peer);
        obj->sub_0xB0(var_80, &msg, peer, true);
        SendCloneCreateReliable(net, peer, obj->type, obj->netid, obj->flags, msg.getBuffer(), msg.getBufferSize());
        sub_8278CCE8(peer, r28);
        MarkNetCloneForPeerCreated(obj, peer, true);
        if(obj->sub_0x48())
        {
            if(GetNetObjSyncData(obj, peer))
                DestroyNetObjSyncData(obj, peer);
            obj->sub_0x44(peer, true);
        }
        if(obj->netid)
            *(int*)(net + ((((obj->netid << 4) + peer) + 0x7DD4) << 2)) = NULL;
    }
    else if(obj->netid)
        *(int*)(net + ((((obj->netid << 4) + peer) + 0x7DD4) << 2))++;
}

void __attribute__((naked)) AttachPedToPedPatch()
{
   __asm("mr %r31, %r3");
   __asm("extsw %r4, %r29");
   __asm("lis %r9, 0x100");
   __asm("ori %r9, %r9, 0xACBC");
   __asm("lwz %r3, 0(%r9)");
   __asm("lis %r9, 0x0070");
   __asm("ori %r9, %r9, 0x7B58");
   __asm("mtctr %r9");
   __asm("bctr");
}

PatchInJump((DWORD*)0x00707B48, AttachPedToPedPatch, FALSE);

bool GenerateNetworkID(int index, QWORD* id)
{
    char gamertag[16];
    char mac[6];

    *id = -1;
    if(IsUserSignedIn(index))
    {
        memset(gamertag, 0, 16);
        if(GetUserName(index, gamertag, 16))
        {
            if(GetMacAddress(mac))
            {
                int v12 = XorData(gamertag, strlen(gamertag), XorData(gamertag, strlen(gamertag), 0));
                QWORD newid = ((((((v15[5] << 8) | v15[2]) << 8) | v15[0]) << 8) | v15[4]) << 32;
                newid ^= v12;
                *id = newid;
                return true;
            }
        }
    }
    return false;
}

player_s*
{
    int _0x00; //sys_net_inet_pton
    int _0x04;
    int _0x08;
    char _0x0C[12]; //sceNpManagerGetNpId
    //0x30
    __int64 _0x30;
    __int64 _0x38;
    
}

struct groupMember_s
{
    CEntity* entity;
    int netid;
};

struct group_s
{
    int _0x00;
    int _0x04;
    groupMember_s members[8];
    float maxSeperation;
    CPedFormation* formationData;
    char peerWhoCreatedGroup;
    char _0x55;
    short followStatus;
    int scriptID;
};

#define OBJECT_REASSIGN 0x20
#define OBJECT_REGISTERED 2

struct _unknown1
{
    char _0x00;
    char _0x01;
    char _0x2;
};

class CNetworkObject
{
    CEntity* entity; //4
    eCloneType type; //8
    short netID; //c
    bool doWeOwnThis; //e
    char owner;
    char creator;
    char otherFlags;
    char flags;
    char _padding1;
    short _0x14;
    int _0x18;
    CNetBlender* blenderData;
    int _0x20;
    char _0x24;
    char _padding2[3];
    _unknown1 _0x28[16];
    int _0x58;
    CNetSyncData* syncs[0x10];
    int _0x9C;
    int ownerShipToken;

    CEntity* GetBaseEntity(); //4
    CEntity* GetBaseEntity(); //8
    CEntity* GetBaseEntity(); //C
    bool ReturnZero(); //10
    CEntity* GetBaseEntity(); //14
    CEntity* GetBaseEntity(); //18
    bool ReturnZero(); //1C
    bool ReturnZero(); //20
    bool ReturnZero(); //24
    bool ReturnZero(); //28
    bool ReturnZero(); //2C
    bool ReturnZero(); //30
    bool ReturnZero(); //34
    void SetCreatorId(int peer); //38
    void ClearCreatorId(); //3c
    void SetupNetBlenderData(); //40
    bool CreateSyncData(int peer, int r5); //44
    bool ReturnOne(); //48
    bool StopSyncing(); //4C
    void sub_82702250(); //50
    void nullsub(); //54
    bool ReturnOne(); //58
    bool sub_82703BC0(int peer); //5C
    bool sub_82702438(); //60
    bool sub_82704390(CNetObjPlayer* r4, bool r5, bool r6); //64
    bool sub_82702378(CNetObjPlayer* r4, bool r5); //68
    bool ReturnOne(); //6C
    bool loc_826E72D0(); //70
    void ChangeOwner(int newOwner, bool r5); //74
    bool ReturnOne(); //78
    bool ReturnZero(); //7C
    void nullsub(); //80
    void loc_827038B0(CNetObjPlayer* r4); //84
    bool ReturnZero(); //88
    void nullsub();  //8C
    bool ReturnZero(); //90
    bool ReturnZero(); //94
    bool ReturnZero(); //98
    void sub_827041A8(int r4, bool r5); //9C
    void* sub_82703938(int* r3, int r4, int r5, int* r6 int* r7); //a0
    bool ReturnZero(); //a4
    void sub_8272F5E0(); //a8
    void* sub_82703200(int* r3, CNetworkEntity* r4, int peer); //ac
    bool sub_82703A30(bool r4, CMessageBuffer* msg, int r6, int r7); //b0
    void* sub_82703AD0(int* r3, CNetworkObject* obj, bool r5, CMessageBuffer* msg, int r7, int r8, int r9); //b4
    bool sub_827045B8(CMessageBuffer* msg, int r5, bool r6); //b8
    bool sub_827046C8(CMessageBuffer* msg, int r5, bool r6); //bc
    bool ReturnZero(); //c0
    bool ReturnOne(); //c4
    int loc_82702420(int r4, int r5); //c8
    bool sub_82703B50(bool r4, CMessageBuffer* msg); //cc
    void nullsub(); //d0
    void nullsub(int r4, int r5, int r6, int r7); //d4
    void sub_82702638(int r4, CMessageBuffer* msg, int r7); //d8
    bool ReturnZero(); //dc
    void loc_82703D08(int r4, int r5); //e0
    void sub_82702980(); //e4
    int loc_826E72D8(int peer); //e8
    void sub_82702A18(int* r4); //ec
    bool ReturnZero(); //f0
    bool ReturnZero(); //f4
    bool ReturnZero(); //f8
};

class CNetObjEntity : public CNetworkObject
{
    int _0xA4;
    int _0xA8;
    bool hasCollision;
    bool visible;
    char _0xAE;
    char _0xAF;
    char _0xB0;
    char _0xB1;
    char _padding1[2];
    int _0xB4;
    char _0xB8;
    char _0xB9;
    char _0xBA;
    char _padding2;

    CEntity* GetBaseEntity() override; //4
    CEntity* GetBaseEntity(); //8
    CEntity* GetBaseEntity(); //C
    bool ReturnZero(); //10
    CEntity* GetBaseEntity(); //14
    CEntity* GetBaseEntity(); //18
    bool ReturnZero(); //1C
    bool ReturnZero(); //20
    bool ReturnZero(); //24
    bool ReturnZero(); //28
    bool ReturnZero(); //2C
    bool ReturnZero(); //30
    bool ReturnZero(); //34
    void SetCreatorId(int peer); //38
    void ClearCreatorId(); //3c
    void SetupNetBlenderData(); //40
    bool CreateSyncData(int peer, int r5); //44
    bool ReturnOne(); //48
    bool StopSyncing() override; //4C
    void sub_826E5C20() override; //50
    void nullsub(); //54
    bool ReturnOne(); //58
    bool sub_82703BC0(int peer); //5C
    bool sub_82702438(); //60
    bool sub_826E5000(CNetObjPlayer* r4, bool r5, bool r6) override; //64
    bool sub_82702378(CNetObjPlayer* r4, bool r5); //68
    bool ReturnOne(); //6C
    bool loc_826E72D0(); //70
    void ChangeOwner(int newOwner, bool r5) override; //74
    bool ReturnOne(); //78
    bool sub_826E4EE8() override; //7C
    void nullsub(); //80
    void loc_827038B0(CNetObjPlayer* r4); //84
    bool nullsub() override; //88
    void nullsub();  //8C
    bool nullsub() override; //90
    bool ReturnZero(); //94
    bool ReturnZero(); //98
    void sub_827041A8(int r4, bool r5); //9C
    void* sub_826E4C98(int* r3, int r4, int r5, int* r6 int* r7) override; //a0
    void sub_826E51F0() override; //a4
    void sub_826E5200() override; //a8
    void* loc_826E7388(int* r3, CNetworkEntity* r4, int peer) override; //ac
    bool sub_826E5260(bool r4, CMessageBuffer* msg, int r6, int r7) override; //b0
    void* sub_826E53C8(int* r3, CNetworkObject* obj, bool r5, CMessageBuffer* msg, int r7, int r8, int r9) override; //b4
    bool sub_827045B8(CMessageBuffer* msg, int r5, bool r6); //b8
    bool sub_827046C8(CMessageBuffer* msg, int r5, bool r6); //bc
    void sub_826E54F8() override; //c0
    int loc_82174080() override; //c4
    int loc_826E5658(int r4, int r5) override; //c8
    bool sub_826E5688(bool r4, CMessageBuffer* msg) override; //cc
    void nullsub(); //d0
    void nullsub(int r4, int r5, int r6, int r7); //d4
    void sub_82702638(int r4, CMessageBuffer* msg, int r7); //d8
    bool sub_826E57F0() override; //dc
    void loc_82703D08(int r4, int r5); //e0
    void sub_82702980(); //e4
    int sub_826E6948(int peer) override; //e8
    void sub_826E5BE8(int* r4) override; //ec
    bool ReturnZero(); //f0
    bool ReturnZero(); //f4
    bool ReturnZero(); //f8
    void sub_826E6E48(); //fc
    bool ReturnZero(); //d0
    float loc_826E5D50(); //d4
    float loc_826E5E18(); //d8
    int CollisionData(int r4, CMessageBuffer* msg); //dc
    int loc_826E74B0(int r4, CMessageBuffer* msg); //e0
    int loc_826E7690(int r4, CMessageBuffer* msg); //e4
    int loc_826E62D8(int r4, CMessageBuffer* msg); //e8
    bool GetVisibility(); //ec
    bool GetCollision(); //f0
    int sub_826E68E0(); //f4
};

class CNetObjDynamicEntity : public CNetObjEntity
{
    int interiorHash;
    int _0xC0;
    int portalRoomId;
    bool loadCollisions;
    char _padding1[3];

    CEntity* GetBaseEntity(); //4
    CEntity* GetBaseEntity() override; //8
    CEntity* GetBaseEntity(); //C
    bool ReturnZero(); //10
    CEntity* GetBaseEntity(); //14
    CEntity* GetBaseEntity(); //18
    bool ReturnZero(); //1C
    bool ReturnZero(); //20
    bool ReturnZero(); //24
    bool ReturnZero(); //28
    bool ReturnZero(); //2C
    bool ReturnZero(); //30
    bool ReturnZero(); //34
    void SetCreatorId(int peer); //38
    void ClearCreatorId(); //3c
    void SetupNetBlenderData(); //40
    bool CreateSyncData(int peer, int r5); //44
    bool ReturnOne(); //48
    bool StopSyncing(); //4C
    void sub_826E5C20(); //50
    void nullsub(); //54
    bool sub_82795AC0() override; //58
    bool sub_82703BC0(int peer); //5C
    bool sub_82702438(); //60
    bool sub_826E5000(CNetObjPlayer* r4, bool r5, bool r6); //64
    bool sub_82702378(CNetObjPlayer* r4, bool r5); //68
    bool ReturnOne(); //6C
    bool loc_826E72D0(); //70
    void ChangeOwner(int newOwner, bool r5) override; //74
    bool ReturnOne(); //78
    bool sub_826E4EE8(); //7C
    void nullsub(); //80
    void loc_827038B0(CNetObjPlayer* r4); //84
    bool nullsub(); //88
    void nullsub(); //8C
    bool nullsub(); //90
    bool ReturnZero(); //94
    bool ReturnZero(); //98
    void sub_827041A8(int r4, bool r5); //9C
    void* sub_826E4C98(int* r3, int r4, int r5, int* r6 int* r7); //a0
    void sub_826E51F0(); //a4
    void sub_82795B70() override; //a8
    void* loc_826E7388(int* r3, CNetworkEntity* r4, int peer); //ac
    bool sub_826E5260(bool r4, CMessageBuffer* msg, int r6, int r7); //b0
    void* sub_826E53C8(int* r3, CNetworkObject* obj, bool r5, CMessageBuffer* msg, int r7, int r8, int r9); //b4
    bool sub_827965F8(CMessageBuffer* msg, int r5, bool r6) override; //b8
    bool sub_82795BB0(CMessageBuffer* msg, int r5, bool r6) override; //bc
    void sub_826E54F8(); //c0
    int loc_82174080(); //c4
    int loc_826E5658(int r4, int r5); //c8
    bool sub_826E5688(bool r4, CMessageBuffer* msg); //cc
    void nullsub(); //d0
    void nullsub(int r4, int r5, int r6, int r7); //d4
    void sub_82795C08(int r4, CMessageBuffer* msg, int r7) override; //d8
    bool sub_82795C98() override; //dc
    void loc_82703D08(int r4, int r5); //e0
    void sub_82702980(); //e4
    int sub_826E6948(int peer); //e8
    void sub_826E5BE8(int* r4); //ec
    bool ReturnZero(); //f0
    bool ReturnZero(); //f4
    bool ReturnZero(); //f8
    void sub_826E6E48(); //fc
    bool ReturnZero(); //d0
    float loc_826E5D50(); //d4
    float loc_826E5E18(); //d8
    int GetSetRoomData(int r4, CMessageBuffer* msg) override; //dc
    int loc_826E74B0(int r4, CMessageBuffer* msg); //e0
    int loc_826E7690(int r4, CMessageBuffer* msg); //e4
    int loc_826E62D8(int r4, CMessageBuffer* msg); //e8
    bool GetVisibility(); //ec
    bool GetCollision(); //f0
    int sub_826E68E0(); //f4
};

class CNetObjPhysical : public CNetObjDynamicEntity
{
    bool attachedToEntity;
    char _0xCD;
    char _0xCE[0x10];
    char _padding1;
    int _0xE0;
    int _0xE4;
    int _0xE8;
    char _padding2[0x24];
    int _0x110;
    int _0x114;
    int _0x118;
    char _padding3[4];
    
    CEntity* GetBaseEntity(); //4
    CEntity* GetBaseEntity(); //8
    CEntity* GetBaseEntity() override; //C
    bool ReturnZero(); //10
    CEntity* GetBaseEntity(); //14
    CEntity* GetBaseEntity(); //18
    bool ReturnZero(); //1C
    bool ReturnZero(); //20
    bool ReturnZero(); //24
    bool ReturnZero(); //28
    bool ReturnZero(); //2C
    bool ReturnZero(); //30
    bool ReturnZero(); //34
    void SetCreatorId(int peer); //38
    void ClearCreatorId(); //3c
    void SetupNetBlenderData() override; //40
    bool CreateSyncData(int peer, int r5); //44
    bool ReturnOne(); //48
    bool StopSyncing() override; //4C
    void sub_826E5C20(); //50
    void nullsub(); //54
    bool sub_82795AC0(); //58
    bool sub_82703BC0(int peer); //5C
    bool sub_82702438(); //60
    bool sub_826E5000(CNetObjPlayer* r4, bool r5, bool r6); //64
    bool sub_82702378(CNetObjPlayer* r4, bool r5); //68
    bool sub_8271F698() override; //6C
    bool loc_8271F758() override; //70
    void ChangeOwner(int newOwner, bool r5) override; //74
    bool ReturnOne(); //78
    bool sub_826E4EE8(); //7C
    void nullsub(); //80
    void loc_827038B0(CNetObjPlayer* r4); //84
    bool loc_8271F7F8() override; //88
    void nullsub(); //8C
    bool nullsub(); //90
    bool ReturnZero(); //94
    bool ReturnZero(); //98
    void sub_82720F30(int r4, bool r5) override; //9C
    void* sub_82721040(int* r3, int r4, int r5, int* r6 int* r7) override; //a0
    void sub_82721368() override; //a4
    void sub_8271F880() override; //a8
    void* loc_826E7388(int* r3, CNetworkEntity* r4, int peer); //ac
    bool sub_8271F8E0(int r4, CMessageBuffer* msg, int peer, bool r7) override; //b0
    void* sub_827213F0(int* r3, CNetworkObject* obj, bool r5, CMessageBuffer* msg, int r7, int r8, int r9) override; //b4
    bool sub_8271FA50(CMessageBuffer* msg, int r5, bool r6) override; //b8
    bool sub_8271FAC0(CMessageBuffer* msg, int r5, bool r6) override; //bc
    void sub_826E54F8(); //c0
    int loc_821C0838() override; //c4
    int loc_8271FB48(int r4, int r5) override; //c8
    bool sub_8271FB78(bool r4, CMessageBuffer* msg) override; //cc
    void nullsub(); //d0
    void nullsub(int r4, int r5, int r6, int r7); //d4
    void sub_8271FCE8(int r4, CMessageBuffer* msg, int r7) override; //d8
    bool sub_8271FED8() override; //dc
    void loc_82703D08(int r4, int r5); //e0
    void sub_82702980(); //e4
    int sub_826E6948(int peer); //e8
    void sub_82720088(int* r4) override; //ec
    bool ReturnZero(); //f0
    bool ReturnZero(); //f4
    bool ReturnZero(); //f8
    void sub_826E6E48(); //fc
    bool ReturnZero(); //d0
    float loc_826E5D50(); //d4
    float loc_826E5E18(); //d8
    int GetSetEntityDamageData(int r4, CMessageBuffer* msg) override; //dc
    int loc_826E74B0(int r4, CMessageBuffer* msg); //e0
    int loc_826E7690(int r4, CMessageBuffer* msg); //e4
    int loc_826E62D8(int r4, CMessageBuffer* msg); //e8
    bool GetVisibility(); //ec
    bool GetCollision(); //f0
    int sub_826E68E0(); //f4
    void GetSetEntityVelocityData(); //f8
    void loc_82720948(); //fc
    void GetSetLastEntityDamageData(); //100
    void GetSetEntityLocationData(); //104
};

struct unknown3
{
    short _0x00;
    char _0x00;
    char _0x01;
    char _0x02;
    char _padding1;
    short _0x04;
    char _0x06;
    char _0x07;
    char _0x08;
    char _padding2;
    short _0x0A;
    char _0x0C;
    char _0x0D;
    char _0x0E;
    char _padding3;
    short _0x10;
    char _0x12;
    char _0x13;
    char _0x14;
    char _padding4[3];
};

struct unknown2
{
    unknown3 _0x00;
    unknown3 _0x18;
};

struct unknown4
{
    int _0x00;
    int _0x04;
    int _0x08;
    int _0x0C;
    int _0x10;
    char _0x14;
    char _padding1[3];
};

class CNetObjPed : public CNetObjPhysical
{
    short _0x120[0x10];
    unknown2 _0x140[0x10];
    short _0x440;
    short _0x442;
    short _0x444;
    short _0x446;
    int _0x448;
    char _0x44C;
    char _0x44D;
    char _0x44E;
    char _0x44F;
    char _0x450;
    bool weaponObjectVisible;
    char _0x452;
    char _0x453;
    char _0x454;
    char _padding1;
    short _0x456;
    short _0x458;
    short targetNetId;
    int targetSeat;
    char _0x460;
    int _0x464;
    unknown4 _0x468;

    CEntity* GetBaseEntity(); //4
    CEntity* GetBaseEntity(); //8
    CEntity* GetBaseEntity(); //C
    bool ReturnZero(); //10
    CEntity* GetBaseEntity() override; //14
    CEntity* GetBaseEntity(); //18
    bool ReturnZero(); //1C
    bool ReturnZero(); //20
    bool ReturnZero(); //24
    bool ReturnZero(); //28
    bool ReturnZero(); //2C
    bool ReturnZero(); //30
    bool ReturnZero(); //34
    void SetCreatorId(int peer); //38
    void ClearCreatorId(); //3c
    void SetupNetBlenderData() override; //40
    bool CreateSyncData(int peer, int r5) override; //44
    bool ReturnOne(); //48
    bool StopSyncing() override; //4C
    void loc_82709490() override; //50
    void loc_82709508() override; //54
    bool loc_82709550() override; //58
    bool loc_827098B0(int peer) override; //5C
    bool sub_82702438(); //60
    bool loc_82709918(CNetObjPlayer* r4, bool r5, bool r6) override; //64
    bool loc_827099C8(CNetObjPlayer* r4, bool r5) override; //68
    bool loc_82709A30() override; //6C
    bool loc_82709AC8() override; //70
    void ChangeOwner(int newOwner, bool r5) override; //74
    bool ReturnOne(); //78
    bool sub_826E4EE8(); //7C
    void nullsub(); //80
    void loc_827038B0(CNetObjPlayer* r4); //84
    bool sub_82709660() override; //88
    void sub_8270CEB0() override; //8C
    bool WriteCloneData() override; //90
    bool ReadCloneData() override; //94
    bool loc_8270D608() override; //98
    void loc_82709B30(int r4, bool r5) override; //9C
    void* sub_82711F00(int* r3, int r4, int r5, int* r6 int* r7) override; //a0
    void loc_82709C38() override; //a4
    void loc_82709C98() override; //a8
    void* loc_826E7388(int* r3, CNetworkEntity* r4, int peer); //ac
    bool sub_82712510(bool r4, CMessageBuffer* msg, int r6, int r7) override; //b0
    void* sub_82712880(int* r3, CNetworkObject* obj, bool r5, CMessageBuffer* msg, int r7, int r8, int r9) override; //b4
    bool sub_8271FA50(CMessageBuffer* msg, int r5, bool r6); //b8
    bool loc_82712A40(CMessageBuffer* msg, int r5, bool r6) override; //bc
    void loc_82709D08() override; //c0
    int sub_821C6C50() override; //c4
    int loc_8270A128(int r4, int r5) override; //c8
    bool sub_82712A90(bool r4, CMessageBuffer* msg) override; //cc
    void nullsub(); //d0
    void nullsub(int r4, int r5, int r6, int r7); //d4
    void sub_8271FCE8(int r4, CMessageBuffer* msg, int r7); //d8
    bool sub_8270D6A0() override; //dc
    void loc_82703D08(int r4, int r5); //e0
    void sub_82702980(); //e4
    int loc_82709EB8(int peer) override; //e8
    void loc_8270A068(int* r4) override; //ec
    bool loc_8270CB08() override; //f0
    bool loc_8270CB08() override; //f4
    bool loc_8270A0D0() override; //f8
    void loc_8270DA50() override; //fc
    bool loc_8270A160() override; //d0
    float loc_826E5D50(); //d4
    float loc_826E5E18(); //d8
    int sub_8270DB70(int r4, CMessageBuffer* msg) override; //dc
    int loc_826E74B0(int r4, CMessageBuffer* msg); //e0
    int loc_826E7690(int r4, CMessageBuffer* msg); //e4
    int loc_8270A628(int r4, CMessageBuffer* msg) override; //e8
    bool GetVisibility(); //ec
    bool sub_8270C2A0() override; //f0
    int sub_826E68E0(); //f4
    void loc_8270A9A8() override; //f8
    void loc_8270A9A8() override; //fc
    void sub_8270AA50() override; //100
    void sub_8270EEA8() override; //104
    void sub_8270B7E0(); //108
};

class CNetObjPlayer : public CNetObjPed
{
    char _0x480;
    char _padding1[3];
    PlayerApperanceData* appearance;
    void* _0x488;
    short standingOnNetId;
    short _0x48E;
    char _padding2[0x70];

    CEntity* GetBaseEntity(); //4
    CEntity* GetBaseEntity(); //8
    CEntity* GetBaseEntity(); //C
    bool ReturnZero(); //10
    CEntity* GetBaseEntity(); //14
    CEntity* GetBaseEntity() override; //18
    bool ReturnZero(); //1C
    bool ReturnZero(); //20
    bool ReturnZero(); //24
    bool ReturnZero(); //28
    bool ReturnZero(); //2C
    bool ReturnZero(); //30
    bool ReturnZero(); //34
    void SetCreatorId(int peer); //38
    void ClearCreatorId(); //3c
    void SetupNetBlenderData(); //40
    bool CreateSyncData(int peer, int r5) override; //44
    bool ReturnOne(); //48
    bool StopSyncing() override; //4C
    void loc_82709490(); //50
    void loc_82709508(); //54
    bool loc_82709550(); //58
    bool loc_827098B0(int peer); //5C
    bool sub_82702438(); //60
    bool ReturnZero(CNetObjPlayer* r4, bool r5, bool r6) override; //64
    bool loc_827099C8(CNetObjPlayer* r4, bool r5); //68
    bool loc_82709A30(); //6C
    bool loc_82709AC8(); //70
    void ChangeOwner(int newOwner, bool r5) override; //74
    bool ReturnZero() override; //78
    bool sub_826E4EE8(); //7C
    void nullsub(); //80
    void loc_827038B0(CNetObjPlayer* r4); //84
    bool loc_827773C8() override; //88
    void loc_82777450() override; //8C
    bool WriteCloneData() override; //90
    bool ReadCloneData() override; //94
    bool loc_82601C98() override; //98
    void loc_82709B30(int peer, bool r5); //9C
    void* loc_827789A8(int* r3, int r4, int r5, int* r6 int* r7) override; //a0
    void loc_82709C38(); //a4
    int loc_82709C98(int* r3, CNetEntity* entity); //a8
    void* loc_826E7388(int* r3, CNetworkEntity* r4, int peer); //ac
    bool loc_82778A38(bool r4, CMessageBuffer* msg, int r6, int r7) override; //b0
    void* loc_82778AB0(int* r3, CNetworkObject* obj, bool r5, CMessageBuffer* msg, int r7, int r8, int r9) override; //b4
    bool sub_8271FA50(CMessageBuffer* msg, int r5, bool r6); //b8
    bool loc_82712A40(CMessageBuffer* msg, int r5, bool r6); //bc
    void ReturnOne() override; //c0
    int loc_821BD988() override; //c4
    int loc_82777D90(int r4, int r5) override; //c8
    bool loc_82778B20(bool r4, CMessageBuffer* msg) override; //cc
    void nullsub(); //d0
    void nullsub(int r4, int r5, int r6, int r7); //d4
    void sub_8271FCE8(int r4, CMessageBuffer* msg, int r7); //d8
    bool loc_82777710() override; //dc
    void loc_82703D08(int r4, int r5); //e0
    void sub_82702980(); //e4
    int loc_82709EB8(int peer); //e8
    void loc_8270A068(int* r4); //ec
    bool loc_827772D8() override; //f0
    bool loc_827772D8() override; //f4
    bool loc_8270A0D0(); //f8
    void nullsub() override; //fc
    bool loc_8270A160(); //d0
    float loc_826E5D50(); //d4
    float loc_826E5E18(); //d8
    int sub_82778B98(int r4, CMessageBuffer* msg) override; //dc
    int loc_826E74B0(int r4, CMessageBuffer* msg); //e0
    int loc_826E7690(int r4, CMessageBuffer* msg); //e4
    int loc_8270A628(int r4, CMessageBuffer* msg); //e8
    bool loc_82777F20() override; //ec
    bool loc_82777FC0() override; //f0
    int sub_826E68E0(); //f4
    void loc_8270A9A8(); //f8
    void loc_8270A9A8(); //fc
    void sub_82777DC8() override; //100
    void sub_8270EEA8(); //104
    void sub_82779A90() override; //108
};

struct unknown5
{
    char _0x00;
    char _0x01;
    char _0x02;
    char _padding1;
    int _0x04;
};

class CNetObjPlayerSyncData
{
    int _0x04;
    unknown5 _0x08;
    char buffer[0x100];
    CMessageBuffer msg; //0x118
    int _0x138[0x20];
    short _0x1B8[0x10];

    int loc_82777150(int peer); //4
    void loc_82777160(int peer, int r5); //8
    void loc_827771B8(); //c
    void nullsub(); //10
    int loc_82777170(int peer); //14
    void loc_82777180(int r4, int r5); //18
    short loc_827771E0(int peer); //1c
    void loc_827771F0(int peer, short r5); //20
    CMessageBuffer* GetSyncMessage(); //24
};

typedef struct RDR_SCO_HEADER
{
    int magic; //0x00 - (0x2524353 only header checked)
    int signature; //0x04
    int compressedSize; //0x08
    int dataKey; //0x0C - (Can only be -3)
    int opcodePageSize; //0x10
    int staticCount; //0x14
    int globalCount; //0x18
    int _0x1C; //stored but not used during reading
    int nativeCount; //0x20
    int _0x24; //unused
    int _0x28; //unused
    int _0x2C; //unused
};

How to decrypt RDR SCO:
Read Header size 0x30
Read amout defined in compressedSize
Decrypt amount defined in compressedSize with AES
Decompress amount defined in opcodePageSize with zlib (unless opcodePageSize is larger than 0x4000, if it is only decompress 0x4000 and contiune with that size till you reach 0 on code size)
Decompress amount defined in (native count << 2)
Decompress amount defined in (static count << 2)
Decompress amount defined in (global count << 2)

typedef struct MSG
{
    byte* buffer; //0x00
    int startLoc;
    int size; //number of bits 0x08 (passes the amount of bytes in size, converted to bits)
    int count; //0x0C
    int bitsWritten;
    int bitsRead;
    byte flag; //flag only 3 bits
};

void InitMSGStruct(MSG* msg);
void SetupWriteMSG(MSG* msg, byte* buffer, int size);
bool CanWeWriteDataToMSG(MSG* msg, int bits);
void PackData(char* buffer, int value, int bits, int offset); //0x8283EDE0 Xbox RDR
void UnpackData(char* buffer, int value, int bits, int offset); //0x8283ED68 Xbox RDR
void UpdateWriteDataMSG(MSG* msg, int bits);
int GetCurrentMSGSize(MSG* msg);
int WriteKeyMSG(int key, byte* buffer, int size);
bool WriteMSGDWORD(MSG* msg, DWORD value, int bits);
bool WriteMSGBYTE(MSG* msg, BYTE value, int bits);
bool WriteMSGBYTERef(MSG* msg, BYTE* value, int bits);
bool WriteMSGBYTEExt(MSG* msg, BYTE value, int bits);
bool WriteMSGDWORDRef(MSG* msg, DWORD* value, int bits);
bool WriteMSGQWORD(MSG* msg, QWORD value, int bits);
bool WriteMSGWORD(MSG* msg, WORD value, int bits);
bool WriteMSGWORDExt(MSG* msg, WORD value, int bits);

int WriteKeyMSG(int key, byte* buffer, int size)
{
    MSG msg;

    InitMSGStruct(&msg);
    if(size >= 4)
    {
        SetupWriteMSG(&msg, buffer, size);
        if(CanWeWriteDataToMSG(&msg, 14))
        {
            PackData(msg.buffer, 0x3246, 14, msg.startLoc + msg.count);
            UpdateWriteDataMSG(&msg, 14);
        }
        WriteMSGDWORD(&msg, (key > 255) ? 1 : 0, 2);
        WriteMSGDWORD(&msg, key, (key ? 255) ? 16 : 8);
    }
    return GetCurrentMSGSize(&msg);
}

void ReadConnectionMSGs(void* r3, int r4, SomeClass* r5)
{
    int messageKey;

    if(r5->_0x00(r4) == 4 && 
        ReadKeyFromMSG(&messageKey, r5->_0x0C.buffer, r5->_0x0C.size))
    {
        if(CMsgGetReadyToStartPlaying.key == messageKey)
            TellUsToStartPlaying(r3, r5->message);
        else if(CMsgStartLocalPlayerPlaying.key == messageKey)
            StartLocalPlayerPlaying(r3, r5->message);
        else if(CMsgInformObjectIds.key == messageKey)
            InformObjectIds(r3, r5->message);
        else if(CMsgVoiceStatus.key == messageKey)
            VoiceStatus(r3, r5->message);
    }
}

bool AreWeHost();
bool SetUsPlaying();
void DebugPrintTellNetResponse(int* teamNumber, bool receiving, short r5, int r6);

bool ReadTellNetMSG(int* teamNumber, int tellNetKey, byte* buffer, int size, int* count)
{
    int key = 0;
    MSG msg;
    bool result = false;

    int readAmount = ReadKeyFromMSG(&key, buffer, size);
    InitMSGStruct(&msg);
    SetupMSGForRead(&msg, buffer + readAmount, size - readAmount);
    if(readAmount != 0 && key == tellNetKey)
    {
        result = true;
        if(!ReadTellNetData(teamNumber, &msg))
            result = false;
    }
    if(count)
        *count = (result) ? GetReadAmount(&msg) + readAmount : 0;
    return (result && (GetReadAmount(&msg) + readAmount) == size);
}

void TellUsToStartPlaying(void* r3, SomeClass* r4)
{
    int teamNumber = -1;

    if(AreWeHost())
        return;
    if(!ReadTellNetMSG(&teamNumber, CMsgGetReadyToStartPlaying.key, r4->buffer, r4->size, NULL))
        return;
    DebugPrintTellNetResponse(&teamNumber, true, r4->_0x34, r4->_0x04);
    if(OurPlayerID == -1)
        return;
    if(!PlayerList[OurPlayerID])
        return;
    PlayerList[OurPlayerID]->team = teamNumber;
    PlayerList[OurPlayerID]->status = 1;
    SetUsPlaying();
}

bool ReadTellNetData(int* teamNumber, MSG* msg)
{
    int var_80 = 0;
    int var_94 = 0;
    int var_84 = 0;
    int currentDayofWeek = 0;
    int hours = 0;
    int minutes = 0;
    bool syncWeather = 0;
    int currentWeather = 0;
    QWORD* var_9C = 0;
    int var_98 = 0;
    int var_88 = 0;
    int var_8C = 0;
    int var_90 = 0;

    bool result = ReadMSGDWORD(msg, &var_80, 32) & ReadMSGDWORD(msg, &var_94, 2);
    dword_830FB0F0->_0x4144 = var_94;
    var_94 = 0;
    var_80 = 0;
    result &= ReadMSGDWORD(msg, &currentDayofWeek, 3);
    result &= ReadMSGDWORD(msg, &hours, 6);
    result &= ReadMSGDWORD(msg, &minutes, 7);
    result &= ReadMSGDWORD(msg, &var_94, 7);
    result &= ReadMSGDWORD(msg, &currentWeather, 32);
    result &= ReadMSGBool(msg, &syncWeather);
    result &= ReadMSGDWORD(msg, &var_84, 32);
    result &= ReadMSGSignedInt(msg, teamNumber, 32);
    if(result)
    {
        SetupTimeVariables(currentDayofWeek, hours, minutes, var_94);
        SetupWeatherVariables(currentWeather, var_84, syncWeather);
    }
    GetRadioSetup(&dword_82D51FA0, &var_9C, &var_98);
    result &= ReadMSGDWORD(msg, &var_80, 32);
    int loop = var_80;
    for(int i = 0; i < loop; i++)
    {
        bool temp = false;
        var_80 = 0;
        if(CanWeReadDataMSG(msg, 8))
        {
            UnpackData(msg->buffer, &var_80, 8, msg->startLoc + msg->count);
            UpdateReadDataMSG(msg, 8);
            temp = true;
        }
        result &= temp;
        temp = false;
        var_84 = 0;
        if(CanWeReadDataMSG(msg, 8))
        {
            UnpackData(msg->buffer, &var_84, 8, msg->startLoc + msg->count);
            UpdateReadDataMSG(msg, 8);
            temp = true;
        }
        result &= temp;
        temp = false;
        if(CanWeReadDataMSG(msg, 32))
        {
            UnpackData(msg->buffer, &var_88, 32, msg->startLoc + msg->count);
            UpdateReadDataMSG(msg, 32);
            temp = true;
        }
        result &= temp;
        temp = false;
        if(CanWeReadDataMSG(msg, 8))
        {
            UnpackData(msg->buffer, &var_8C, 8, msg->startLoc + msg->count);
            UpdateReadDataMSG(msg, 8);
            temp = true;
        }
        result &= temp;
        temp = false;
        if(CanWeReadDataMSG(msg, 8))
        {
            UnpackData(msg->buffer, &var_90, 8, msg->startLoc + msg->count);
            UpdateReadDataMSG(msg, 8);
            temp = true;
        }
        result &= temp;
        if(i < var_98)
        {
            byte* radioData = (byte*)var_9C[i];
            radioData[4] = var_80;
            radioData[5] = var_84;
            radioData[6] = var_8C;
            radioData[7] = var_90;
        }
    }
    WriteRadioSetup(&dword_82D51FA0, var_9C, var_98);
    return result;
}

void StartLocalPlayerPlaying(void* r3, SomeClass* r4)
{
    int key = 0;
    MSG msg;

    int readAmount = ReadKeyFromMSG(&key, r4->buffer, r4->size);
    InitMSGStruct(&msg);
    SetupMSGForRead(&msg, readAmount + buffer, size - readAmount);
    if(readAmount && key == CMsgStartLocalPlayerPlaying.key && GetReadAmount(&msg) + readAmount == size)
    {
        DebugLocalStartPlaying(NULL, true, r4->_0x34, r4->_0x04);
        Peer_s* peer = GetPeerForConnection(r3, r4->_0x04);
        if(peer && DoesPlayerHaveID(peer))
        {
            player_s* player = GetPlayerStruct(GetPeerID(peer));
            if(player != 0 && player->status < 2)
                player->status = 2;
        }
    }
}

void InformObjectIds(void* r3, SomeClass* r4)
{
    Object_s object;

    Peer_s* peer = GetPeerForConnection(r4->_0x04);
    if(peer && DoesPlayerHaveID(peer))
    {
        object.peer = GetPeerID(peer);
        object.readCount = NULL;
        ReadInformObjectsMSG(&object, CMsgInformObjectIds.key, r4->buffer, r4->size, NULL);
    }
}

bool ReadInformObjectsMSGData(Object_s* object, MSG* msg)
{
    int count msg->count;
    DebugPrint("\tUNPACKING_OBJECT_ID_DATA\r\n");
    UnpackObjectIDs(&dword_83125DC0, object->peer, msg);
    object->readCount = msg->count - count;
}

//struct
var_460 main SomeClass
buffer = r31 + 24
size = 3EA //0x1F50

var_460{
    int empty;
    vpointer CMessageBuffer
    MSG
}

RDR Messages
netTimeSyncMsg
PartyAssignLeaderMsg
CMsgArrayElementsAck
CMsgArrayRegistration
CMsgArrayElements
NetCreatorWeather::CreationEvent
NetCreatorGOHPickup::CreationEvent
NetCreatorClient::CreationEvent
NetCreatorGOHProp::CreationEvent
NetCreatorGOHActor::CreationEvent
NetActorEvent
NetReadyForObjects
NetReassignResponseMsg
NetReassignConfirmMsg
NetReassignNegotiateMsg
NetTimeOfDay::TODAndAccelerationEvent
NetTimeOfDay::AccelerationFactorEvent
NetTimeOfDay::TimeOfDayEvent
NetPickup::GivePickupItemEvent
NetPickup::InvalidPickupEvent
NetPickup::TakePickupEvent
NetLasso::LassoUseEvent
NetLasso::LassoHandleAttachmentActorEvent
NetLasso::LassoReleaseAndReelInEvent
NetLasso::LassoDragDamageEvent
NetDoorEvent
NetDoorInfo
NetDoorRequestReply
NetMelee::RemoteKnockoutEvent
NetGringo::NetGringoEvent
NetTrain::RemoteSetEngineEnabledEvent
NetTrain::RemoteMaxDecelEvent
NetTrain::RemoteMaxAccelEvent
NetTrain::RemoteAutopilotEnabledEvent
NetTrain::RemotePositionEvent
NetTrain::RemoteTargetPosEvent
NetTrain::RemoteTargetSpeedEvent
NetProjectile::RemoteReloadEvent
NetProjectile::RemoteDamageFailedEvent
NetPropEvent
NetPropRequestReturn
NetActorDeath
NetGOHMovable::NetCheckObjectInGC
NetGOHMovable::NetObjectNotInGC
NetBandWithAllowanceMsgAck
DrVNetController::OneOffSyncEvent
NetObjectBase::DataSyncMsg
NetObjectBase::NetObjectVerifyOwnerResponseEvent
NetObjectBase::NetObjectVerifyOwnerEvent
NetObjectBase::NetObjectRejectOwnershipEvent
NetObjectBase::NetObjectTransferOwnershipEvent
NetObjectBase::NetObjectGrantOwnershipEvent
NetObjectBase::NetObjectOwnershipDeniedEvent
NetObjectBase::NetObjectRequestOwnershipEvent
NetObjectCreatedObject
NetObjectLocallyDestroyedEvent
NetObjectRemoveEvent
NetResendAllEvent
DataSyncMessagePacker::PackedMsg
NetObjectRequestStatusResponseEvent
NetObjectRequestStatusEvent
NetDoorShouldSendInfo
NetDoorRequest
NetMelee::RemoteDamageEvent
NetVehicle::RemoteLocationEvent
NetVehicle::RemoteOccupantEvent
NetProjectile::RemoteExplodeTargetEvent
NetProjectile::RemoteThrowingEvent
NetProjectile::RemoteExplosionEvent
NetProjectile::RemoteDamageViewerEvent
NetProjectile::RemoteDamageEvent
NetProjectile::RemoteLaunchEvent
NetObjectManager::NetObjectRejectOwnershipMultipleEvent
NetObjectManager::NetObjectOwnershipMultipleDeniedEvent
NetObjectManager::NetObjectTransferOwnershipMultipleEvent
NetObjectManager::NetObjectGrantOwnershipMultipleEvent
NetObjectManager::NetObjectRequestOwnershipMultipleEvent
NetBandWithAllowanceMsg
CopyTrackerMgr::NetCopyTrackerSingleMsg
CopyTrackerMgr::NetCopyTrackerFullMsg
NetObjectBase::NetObjAckMsg
NetObjectRequestEvent
BootPeerMsg
TitleJpnSyncMsg
YouInvitedGamerMsg
BanGamerAckMsg
BanGamerMsg
VoteToKickMsg
snuMsgGroupJoinCommand
CMsgScriptLeaveAck
CMsgScriptLeave
CMsgScriptHandshakeAck
CMsgScriptHandshake
CMsgScriptJoinHostAck
CMsgScriptJoinAck
CMsgScriptJoin
rdr2netscript::NetScriptEvent_StartNewScript
rdr2netscript::NetScriptEvent_NetScriptMsg
rlDbMsgReadRecordsReply
rlDbMsgGetNumRecordsReply
rlDbMsgProgress
snMsgMigrateHostResponse
snMsgJoinResponse
snMsgGamerMatchInfoResponse
snMsgRegisterForMatchResponse
snMsgMigrateHostRequest
snMsgConfigResponse
rlMsgSearchResponse
netComplaintMsg
snuMsgGroupJoinResponse
snuMsgGroupJoinRequest
snuConnectionQosMessageAck
snuConnectionQosMessage
snMsgRegisterForMatchRequest
snMsgJoinRequest
snMsgAddGamerToSessionCmd
rlMsgQosProbeRequest
snMsgRequestGamerInfo
snMsgSessionMemberIds
snMsgSetInvitableCmd
snMsgChangeSessionAttributesCmd
snMsgGamerMatchInfoRequest
snMsgStartMatchCmd
snMsgRegisterForMatchRequest
snMsgRemoveGamersFromSessionCmd
snMsgConfigRequest
rlMsgSearchRequest
MigrateHostMsg
snuHostDataSyncMsg
snuGamerDataSyncMsg
rlMsgQosProbeResponse
snuGamerMuteMsg
snuGamerUnmuteMsg
rlDbMsgGetNumRecordsRequest
rlDbMsgReadRecordsRequest
PartyInviteMsg
PartyRejectMsg
netDuelDrawMsg

GTA V Messages
MsgTransitionLaunch
MsgCheckQueuedJoinRequestReply
CRoamingJoinBubbleMsg
CRoamingRequestBubbleMsg
msgRequestKickFromHost
MsgRadioStationSync
CRoamingInitialBubbleMsg
CRoamingJoinBubbleAckMsg
playerDataMsg
CMsgJoinRequest
CMsgJoinResponse
MsgRequestTransitionParameters
MsgTransitionParameters
MsgTransitionParameterString
MsgTransitionGamerInstruction
MsgTransitionLaunchNotify
MsgTransitionToGameStart
MsgTransitionToGameNotify
MsgTransitionToActivityStart
MsgTransitionToActivityFinish
MsgReserveSlots
MsgReserveSlotsAck
MsgBlacklist
MsgKickPlayer
MsgRadioStationSyncRequest
MsgCheckQueuedJoinRequest
MsgCheckQueuedJoinRequestInviteReply
MsgPlayerCardSync
MsgPlayerCardRequest
snMsgSessionAcceptChat
CMsgVoiceStatus
MsgTextMessage
snMsgHostLeftWhilstJoiningCmd
snMsgStartMatchCmd
snMsgSetInvitableCmd
snMsgEndMatchCmd
snMsgConfigRequest
snMsgRemoveGamersFromSessionCmd
snMsgRegisterForMatchRequest
snMsgGamerMatchInfoRequest
snMsgChangeSessionAttributesCmd
snMsgSessionMemberIds
snMsgRequestGamerInfo
rlMsgQosProbeRequest
snMsgJoinRequest
snMsgAddGamerToSessionCmd
snMsgJoinResponse
snMsgMigrateHostRequest
snMsgMigrateHostResponse
snMsgRegisterForMatchResponse
snMsgGamerMatchInfoResponse
rlSessionDetailRequest
rlSessionDetailResponse
rlMsgSearchRequest
rlMsgSearchResponse
msgScriptLeave
msgScriptLeaveAck
msgScriptBotHandshakeAck
msgScriptBotLeave
msgScriptMigrateHostFailAck
msgScriptHostRequest
msgScriptMigrateHost
msgScriptNewHost
msgScriptVerifyHost
msgScriptVerifyHostAck
msgScriptJoin
msgScriptJoinAck
msgScriptJoinHostAck
msgScriptHandshake
msgScriptHandshakeAck
msgScriptBotJoin
msgScriptBotJoinAck
msgScriptBotHandshake
msgUpdate
cloneSyncMsg
packedCloneSyncACKsMsg
reassignNegotiateMsg
reassignConfirmMsg
nonPhysicalDataMsg
msgUpdateAck
CMsgPackedEvents
CMsgPackedEventReliablesMsgs
packedReliablesMsg
reassignResponseMsg
requestObjectIdsMsg
informObjectIdsMsg

class CMessageBuffer
{
    MSG msg;
    char buffer[0x3E8];

    int sub_82165060() { return 0; }
    void nullsub_1() {};
};


//IV Messages
struct MsgViralKillMe
{
 //empty
};

struct MsgKickPlayer
{
    QWORD netId; //playerStruct->_0x30
    DWORD kickType;
};

//Everything after Version is disregarded
struct MsgJoinRequest
{
    DWORD version; //0x82D553A0
    char padding0[4];
    BYTE playerId;
    char padding1[3];
    DWORD color; 
    DWORD team;
    DWORD _0x14; //PlayerNet->_0x14
    QWORD _0x18; //sub_826FEA70
    DWORD _0x20; //PlayerNet->_0x24
    DWORD _0x24; //PlayerNet->_0x2C
    DWORD _0x28; //PlayerNet->_0x28
    bool _0x2C; //0x82B39504
};

struct MsgRejoin
{
    QWORD hashedMacAddress; //playerStruct->_0x28
    DWORD _0x08; //0x8310CF60->_0x44 something with party
    DWORD clientVars_hostData;  
};

struct CMsgArrayElements
{   
    CMessageBuffer elements;
    //DWORD size; //MSG->count
    //char* buffer; //packed as a msg MSG->buffer
};

struct MsgGamerRankBroadCast
{
    DWORD playerCash; 
    DWORD _0x04; //sub_826DC168
};

struct MsgGamerRank 
{
    DWORD playerCash; 
    DWORD _0x04; //sub_826DC168
};

struct MsgGamerRankRequest
{
 //empty
};

struct CMsgStartLocalPlayerPlaying
{
 //empty
};

struct rlMsgQosProbeResponse
{
 //empty
};

struct CMsgPackedEvents
{
    DWORD eventCount;
    CMessageBuffer events;
    //DWORD size; //from MSG->Count
    //char* buffer; //from MSG->Buffer
};

struct CMsgPackedEventReliablesMsgs
{
    DWORD eventAckCount;
    CMessageBuffer eventAcks;
    DWORD eventReplyCount;
    CMessageBuffer eventReplys;
};

struct CMsgCloneSync
{
    DWORD networkTime;
    WORD _0x04; //ped net id? //Technically a CMessageBuffer here they just replace the virtual pointer with net id
    char padding[2];
    MSG cloneData;
};

struct CMsgPackedReliables
{
    DWORD createsCount;
    CMessageBuffer creates;
    DWORD createAcksCount;
    CMessageBuffer createAcks;
    DWORD removesCount;
    CMessageBuffer removes;
    DWORD removeAcksCount;
    CMessageBuffer removeAcks;
};

enum CreateType
{
    PLAYER,
    PED,
    DUMMYPED,
    AUTOMOBILE,
    OBJECT,
    BIKE,
    TRAIN,
    BOAT,
    HELI,
    PLANE,
    INVALID_OBJECT
};

struct CMsgPackedReliablesCreateBuffer
{
    CreateType type;
    DWORD createFlags;
    DWORD messageSize;
    struct 
    {
        DWORD _0x00;
        DWORD token;
    }
};

//plenty more like task data and other stuff I couldn't figure out
struct CreatePlayerMSG
{
    DWORD playerId;
    DWORD modelHash;
    DWORD ownerFlags;
    DWORD ownerToken;
    DWORD modelFlags;
    DWORD portalRoomId;
    DWORD interiorHash;
    bool loadCollision;
    bool damageFlag1;
    bool damageFlag2;
    bool damageFlag3;
    DWORD _somethingWithPoolType;
    bool weaponObjectVisible;
    WORD targetVehicle;
    DWORD currentSeat;
    DWORD flags1; //Never Target Ped, Block Non Temp Events, Keep tasks after cleanup, suffer crit hits, target priority, drop weapons, can drag out of cars, can drown 
    DWORD ringState;
    DWORD wantedLevel;
    DWORD fakeWantedLevel;
    DWORD playerTeam;
    float airDragMulti;
    bool spectating;
    DWORD standingOnNetObject;
    DWORD armour;
    DWORD weaponDamageType;
    DWORD voiceHash;
    DWORD relationGroup;
    DWORD normalDecisionMakerType;
    DWORD groupDecisionMakerType;
    DWORD combatDecisionMakerType;
    DWORD combatGroupDecisionMakerType;
};

struct MsgTvtReservationRequest
{
    char _0x00[0x80];
    DWORD _0x80; //size of _0x00
    char padding[4];
    QWORD networkIds[0x20];
    DWORD networkIdCount;
};

struct MsgBlacklist
{
    QWORD _0x00; //sub_826F86D0 + 0x120
    ProfileIds profile; //size 0x10
};

enum DenyType
{
    MP_UNKNOWN,
    MP_BLACKLISTED,
    MP_WRONGVERSION,
    MP_SESSION_FULL
};

struct CMsgDenyJoin
{
    DenyType type;
};

struct MsgTvtSummons
{
    QWORD _0x00; //sub_827C9A00
    char _0x08[0x3C]; //sub_827C9930
    DWORD _0x44; //sub_827C9B40->_0x110
    DWORD _0x48; //sub_827CA9F8
    DWORD _0x4C; //0x82B39504
};

struct CMsgHostData
{
    DWORD networkTime;
};

struct CMsgGetReadyToStartPlaying
{
    DWORD team; 
    //other data is sent its just not packed in the struct
};

//None of this data is actually sent, other data is sent its just not packed in the struct
struct CMsgInformObjectIDs
{
    BYTE playerIndex;
    char padding[3];
    DWORD size;
};

struct CMsgInformObjectIDsData
{
    DWORD _0x00; //sent as 0 always
    WORD inUseObjectId[DYNAMIC]; //looped till something so could be 0 could be 100
    DWORD inUserObjectIdCount;
    DWORD another0;
    WORD freeObjectId[DYNAMIC]; //looped till something
    DWORD freeObjectIdCount;
};

struct CMsgVoiceStatus
{
    DWORD voiceStatus;
};

struct CMsgPeerData
{
    BYTE playerId;
    char padding1[3];
    DWORD color; 
    DWORD team;
    DWORD _0x14; //PlayerNet->_0x14
    QWORD _0x18; //sub_826FEA70
    DWORD _0x20; //PlayerNet->_0x24
    DWORD _0x24; //PlayerNet->_0x2C
    DWORD _0x28; //PlayerNet->_0x28
    bool _0x2C; //0x82B39504
};

struct CMsgReassignNegotiate
{
    BYTE reassignFlags;
    char padding[3];
    DWORD objectCount;
    DWORD cycle;
    CMessageBuffer* buffer;
    DWORD size;
    DWORD checkSize; //not sent just checked
};

struct CMsgReassignConfirm
{
    BYTE reassignFlags;
    char padding[3];
    DWORD myObjects;
    DWORD theirObjects;
    DWORD cycle;
    CMessageBuffer* buffer;
    DWORD size;
    DWORD checkSize; //not sent just checked
};

enum ReassignType
{
    IGNORE,
    NOT_READY,
    NOT_REASSIGNING,
    PROCESSED,
    FINISHED
};

struct CMsgReassignResponse
{
    BYTE reassignFlags;
    bool negotiate;
    char padding[2];
    ReassignType type;
};

struct netTimeSyncMsg
{
    DWORD _0x00;
    DWORD _0x04;
    DWORD _0x08;
    DWORD _0x0C;
};

struct netComplaintMsg
{
    QWORD _0x00;
    QWORD _0x08[0x40];
    DWORD count;
};

bool ExecuteReliablesMSG(NetworkData* net, MSGData* msg)
{
    CMsgReliables reliables;

    SetupCMsgReliables(&reliables);
    if(!ReadMsgPackedReliablesData(&reliables, CMsgPackedReliables.key, msg->msg, msg->size, nullptr))
        return false;
    peer_s peer = GetPeerForConnection(net->connectionData, msg->peerid);
    if(msg->peerid == -1 || !AreWePlayingInNetworkGaem() || !peer)
        return false;
    printf("Unpacking Reliables\n");
    printf("Num creates %i\n", reliables->numCreates);
    printf("Num create acks %i\n", reliables->numCreateAcks);
    printf("Num removes %i\n", reliables->numRemoves);
    printf("Num remove acks %i\n", reliables->numRemovesAcks);
    UnpackCloneCreateData(net, reliables->createData, GetPeerID(peer));
    UnpackCloneCreateAckData(net, reliables->createAckData, GetPeerID(peer));
    UnpackCloneRemoveData(net, reliables->removeData, GetPeerID(peer));
    UnpackCloneRemoveAckData(net, reliables->removeAckData, GetPeerID(peer));
    return true;
}

void UnpackCloneCreateData(NetworkData* net, CMsgCreateData* msgData, byte peer)
{
    MSG* msg = msgData->buffer;
    char objectBuffer[0x80];
    CMessageBuffer buffer;

    while(GetCMessageSize(msg) - GetCMessageCount(msg) >= 30)
    {
        CloneType type = PLAYER;
        if(CanWeReadDataMSG(msg, 4))
        {
            UnpackData(msg->buffer, &type, 4, msg->count + msg->startLoc);
            UpdateReadDataMSG(msg, 4);
        }

        short netId;
        ReadCMessageBufferShort(msg, &netId);

        int createFlags = 0;
        if(CanWeReadDataMSG(msg, 4))
        {
            UnpackData(msg->buffer, &createFlags, 4, msg->count + msg->startLoc);
            UpdateReadDataMSG(msg, 4);
        }

        int objectSize = 0;
        if(CanWeReadDataMSG(msg, 10))
        {
            UnpackData(msg->buffer, &objectSize, 10, msg->count + msg->startLoc);
            UpdateReadDataMSG(msg, 10);
            if(objectSize)
                UnpackMSGBuffer(msg, objectBuffer, objectSize, 0);
        }
        SetupCMessageBuffer(&buffer, objectBuffer, (objectSize >> 3) + 1, 0, true);
        CloneNetworkObeject(net, peer, type, netId, createFlags, &buffer);
    }
}

sub_826ED6B0(netdata* r3, peerdata* r4, )

struct cloneSyncData
{
    int networkTime;
    short _0x04;
    CMessageBuffer _0x08
};

void CloneNetworkObject(NetData* net, int peerId, CloneType_t type, short networkId, int flags, CMessageBuffer* data);

typedef struct timeSync
{
    int _0x00;
    int _0x04;
    int _0x08;
    int _0x0C;
};

void PRINT_BIG(native_s* call)
{
    char* gxt = call->params[0];
    float time = call->params[1];
    bool enable = call->params[2];
    int unk1 = call->params[3];
    char* str = call->params[4];

    if(!RDRUIGameClass)
        return;
    AllocatedMessage* message = RDRUIGameClass->AllocateMessage(gxt, time, enable, 1, true);
    if(message)
    {
        RDRUIGame_HashMessage(messsage, str);
        RDRUIGameClass->DisplayMessage(message, 0, unk1);
    }
}

int* GetPlayerActor(int* out, int playerIndex)
{
    int unk1, someid;

    sub_822C80C8(&unk1, &sagPlayerMgrClass, playerIndex);
    if(!sub_822C9600(&unk1))
    {
        LogError("GET_PLAYER_ACTOR: invalid player index %d", playerIndex);
        *out = NULL;
    }
    else
    {
        int* value = sub_822C80F8(&someid, &unk1);
        short value2 = *(short*)(((((short)*value << 3) | ((short)*value >> 29)) + *(int*)0x8301F140) + 4);
        *out = (value2  == (short)*value) ? *(int*)(*(int*)(((*value >> 13) & 0x7FFF8) + *(int*)0x8301F140) + 0xF4);
    }
    return out;
}

typedef struct AllocatedMessage
{
    int _0x00;
    int flags;
    int _0x08;
    float time;
    int _0x10;
    int _0x14;
    int _0x18;
    int _0x1C;
    int _0x20;
    bool _0x24;
    char _padding[0x1F];
    int _0x44;
    int _0x48;
    int _0x4C;
    int _0x50;
};

AllocatedMessage* messsage RDRUIGame_AllocateMessage(RDRUIGame* this, char* gxt, float time, bool useStringTable, int flag, bool searchForMessage)
{
    if(!this->_0x298 || !gxt)
        return NULL;

    if(searchForMessage)
    {
        for(int i = 0; i < 6; i++)
        {
            if(this->DoesMessageAlreadyExist(gxt, i, useStringTable))
            {
                printf("RDRUIGame::AllocateMessage - Attempt to allocate message %s, which already exists. Returning NULL.", gxt);
                return NULL;
            }
        }
    }   

    if(!this->_0x298->_0x0C)
        return NULL;
    
    AllocatedMessage* message = sub_82422138(this->_0x298->_0x0C, 0);
    if(!message)
        return NULL;

    ZeroMemory(message, sizeof(AllocatedMessage));
    message->_0x10 = -1;
    message->time = 0.0f;
    message->_0x4C = -1;
    message->_0x50 = -1;
    message->_0x00 = sub_8244A0A8(this, useStringTable ? gxt : UIStringTable->GetString(gxt));
    message->flags |= flag;
    message->time = time;
    return message;
}

void LAUNCH_NEW_SCRIPT(native_s* call)
{
    int scriptId;
    RDRStartNewScript(&scriptId, call->params[0], 0, 0, call->params[1] ? call->params[1] : 0x200);
    call->returns[0] = scriptId;
}

int* RDRStartNewScript(int* scriptId, char* scriptName, int r5, int r6, int stackSize)
{
    char scriptPath[0x80];

    sagFullScriptContext* scriptContext = GetCurrentScriptThread()->scriptContext;
    if(!scriptName || !scriptContext || !scriptContext->path)
    {
        LogError("Invalid startup values for RDRStartNewScript");
        *scriptId = 0;
        return scriptId;
    }

    if(!DoesScriptExist(scriptName, scriptPath, scriptContext))
    {
        LogError("Trying to start a script the DoesScriptExist could not find!");
        *scriptId = 0;
        return scriptId;
    }

    sagFullScriptContext* newScriptCxt = scriptContext->SetupNewScriptCxt(scriptPath, scriptContext, r5, r6);
    if(!newScriptCxt)
    {
        *scriptId = 0;
        return scriptId;
    }

    if(noscriptstreaming->enable)
    {
        if(MountScript(newScriptCxt, r5, r6, 0, 0))
        {
            FinalizeScriptContext(scriptContext, newScriptCxt);
            *scriptId = newScriptCxt->id;
            return scriptId;
        }
        LogError("Failed to mount new script %s", scriptPath);
        newScriptCxt->Delete();
        *scriptId = 0;
        return scriptId;
    }
    else
    {
        RequestScript(scriptPath, -12.0f);
        FinalizeScriptContext(scriptContext, newScriptCxt);
        *scriptId = newScriptCxt->id;
        return scriptId;
    }
}

extern _native void UNK_0x27A00456(char* pram0)l //seems to setup a class for metric report of deed
extern _native void UNK_0x120E6123(char* pram0)l //something with metric deed
extern _native void UNK_0x2547029C(char* pram0, int pram1)l //sets up up class for metric report of generic int
extern _native void UNK_0x6F6D942B(char* pram0, char* pram1, int pram2, char* pram3, int pram4, char* pram5, int pram6)l //setups up class for metric report of generic int 3
extern _native void UNK_0x713B1D7F(char* pram0, char* pram1)l //sets up up class for metric report of generic string
extern _native void UNK_0x9C80A3A4(char* pram0, char* pram1, int pram2, int pram3, int pram4)l //seems to setup a class for metric report of deed stuff param0 can only be (START, FAIL, COMPLETE, CANCEL)
extern _native void UNK_0x4585821E(char* pram0, int pram1, int pram2, int pram3)l //sets up class for deed complete metric report
extern _native void UNK_0x46C39437(char* pram0, int pram1, int pram2, int pram3, int pram4, char* pram5)l //sets up MPCoopComplete metric report

//ClearBounty
void Function_38()
{
    void* frame2;
    int frame3;

    Function_18();
    if(GetGlobal(3403) != 0)
    {
        SetGlobal(3403, 0);
        SetGloabl(3405, 0);
        if(IS_FACTION_VALID(GetGlobal(26361)))
            _SET_FACTION_STATUS_TWOWAY(GetGlobal(26361), 2, 2);
        _SET_FACTION_STATUS_TWOWAY(8, 2, 2);
        _SET_FACTION_STATUS_TWOWAY(10, 2, 2);
        frame2 = GetGlobalP(26316);
        frame3 = *(int*)((240 * 4) + frame2);
        int frame4 = *(int*)((256 * 4) + frame2);
        if(IS_SCRIPT_VALID(frame3))
            TERMINATE_SCRIPT(frame3);
        if(IS_SCRIPT_VALID(frame4))
            TERMINATE_SCRIPT(frame4);
        SetGlobal(13111, -1);
    }
    RELEASE_LAYOUT_OBJECTS(GetGlobal(26314));
    frame2 = GetGlobalP(26316);
    frame3 = *(int*)((240 * 4) + frame2);
    if(IS_SCRIPT_VALID(frame3))
        TERMINATE_SCRIPT(frame3);
}

void Function_18()
{
    int* array1 = (int*)GetGlobalP(26401);
    array1[*(int*)(GetGlobalP(26361) + 32] = 0;
    int* array2 = (int*)GetGlobalP(34581);
    int* array3 = (int*)(GetGlobalP(26401) + 2220);
    int arrayIndex1 = array3[*(int*)(GetGlobalP(26361) + 32)];
    array2[arrayIndex1] = TO_FLOAT(0);
    *(int*)(GetGlobalP(26401) + 8848) = 0;
    int* array4 = (int*)(GetGlobalP(26401) + 36);
    array4 = &array4[*(int*)(GetGlobalP(26361) + 32)];
    int* array5 = array4[0];
    array5[3] = 11;
}

WeapDef* GetWeapDef(int weaponId)
{
    WeapDef* def = (WeapDef*)0x15C7D70;
    if(weaponId <= 59)
        def += (r3 << 4) + (r3 << 8);
    return def;
} //sub_66C248

//fx?//
// 0xA5A6A3E3 - dead native
// 0x3736FF43 - returns 0
// 0x065B4197 - returns 0
// 0x21588246 - CREATE_DECAL
// 0x7BCE4845 - looks to be spawning
// 0x9E54C297 - looks to be spawning
// 0x013A0D25 - AT_FIRED_LAST
// 0x1182C34F - no idea
// 0xD0FB6AF0 - no idea
// 0xC00F8181 - no idea
// 0x4897DD37 - no idea
// 0x6E946AF8 - no idea
// 0xB6CA7EBF - no idea
// 0x4710FD93 - RESET_ANALOG_POSITIONS
// 0x6A0A241A - no idea
// 0xFA43DCC5 - no idea
// 0xEC906A7A - no idea
// 0xC9FCD3EC - no idea
// 0x47A8DDED - no idea
// 0x3B32AB84 - something with rainbow
// 0xCBDD5832 - REMOVE_GLOW_INDICATOR
// 0x1065D334 - CREATE_OBJECT_GLOW
// 0xFC261530 - DESTROY_OBJECT_GLOW
// 0x1EE7153B - something with zombie textures
// 0x5685A440 - no idea
// 0x50904C66 - no idea
// 0x807C9D01 - CLEAR_PLAYER_BLOOD
// 0x9D9E093E - no idea
// 0x32F2D6F1 - no idea
// 0xA257C16D - BURN_ACTOR
// 0x3627F773 - no idea
// 0x48123591 - something with reading vfx files
// 0xA0AE0C98 - no idea
/////world enviro/fx
// 0x9A93E7CA - no idea
// 0x59A7835E - no idea
// 0x25690082 - something with a reseting a clear request
// 0xE92C3435 - SET_DUST_LEVEL
// 0xDB86F53B - SET_DUST_LEVEL_MODIFIER
// 0x8BA565F7 - _SET_DUST_LEVEL2
// 0xB8E09389 - _SET_DUST_LEVEL3
// 0x9AA8A1B1 - no idea
// 0x002B0698 - no idea
// 0x57478561 - no idea
// 0x39B0CFE5 - no idea
// 0xDCAE6935 - SET_VEHICLE_APPOINTMENT_TARGET
// 0x8CF15FCB - something with zombiedlcmanager
// 0x4A8066FB - something with zombie
// 0x1DDB57A6 - something with zombie
// 0x88863344 - something with zombiedlcmanager
// 0xE7371670 - something with zombiedlcmanager
// 0x03E2B631 - something with zombiedlcmanager
// 0xCA840DBB - no idea
// 0x4F3F3CA5 - no idea
// 0xC587FA2B - CREATE_FIRE_ON_OBJECT
// 0x8011737F - dead native
// 0x5402321A - CREATE_FIRE_PROPERTY
// 0x2AC74780 - GET_FIRE_PROPERTY
// 0x466C02BA - dead native
// 0xEC3A9EBB - dead native
// 0xADB3E8D9 - something with replacing top level sector
// 0x08D06543 - something with reading boudingbox.dlc
// 0xAD5613FD - ENABLE_WORLD_SECTOR
// 0xB511D087 - DISABLE_WORLD_SECTOR
// 0x7ECE15BE - ENABLE_CHILD_SECTOR
// 0x4E6A78B5 - HIDE_CHILD_SECTOR
// 0x63A83655 - SHOW_CHILD_SECTOR
// 0xBBAE9CBD - FIRE_CREATE_HANDLE
// 0xA488E930 - no idea
// 0xB14B936A - FIRE_RELEASE_HANDLE
// 0xD2BB733E - _RELEASE_INFINITE_FIRE_DESCRIPTOR
// 0x91396EB7 - no idea
// 0x9679CF84 - FIRE_CREATE_ON_ACTOR
// 0xB65ADFAC - FIRE_CREATE_IN_VOLUME
// 0x30C4CA99 - FIRE_IS_ACTOR_ON_FIRE
// 0x15001332 - no idea
// 0xF635B9EA - FIRE_STOP_ON_ACTOR
// 0x11A65FFB - _EXTINGUISH_FLAMES_IN_VOLUME
// 0x15683736 - FIRE_GET_OWNER
// 0x3D5D3B26 - _SET_FIRE_ATTACHED_DAMAGE_ALLOWED
// 0xDEE6523D - no idea
// 0x3DD3E1EB - COUNT_FLAMES_IN_VOLUME
// 0x28DAED2A - FIRE_ARE_ANY_FLAMES_IN_VOLUME
//explosions stuff??
//0x651F6299 - no idea
//weapon stuff?
//0x4372593E - _SET_AMMO_OF_TYPE

void NET_ITERATION_EVENT(Object obj) //27233
{
    if(IS_OBJECT_VALID(obj))
    {
        if(GET_OBJECT_TYPE(obj) == 15)
        {
            Actor frame3 = GET_ACTOR_FROM_OBJECT(obj);
            if(IS_ACTOR_VALID(frame3) && IS_ACTOR_PLAYER(frame3))
            {
                int frame4 = GET_ACTOR_SLOT(frame3);
                if(IS_SLOT_VALID(frame4))
                {
                    if((!Function_209(1) || (Function_210(GET_LOCAL_SLOT(), frame4) && !Function_209(2)) || Function_209(4))
                        Function_211(frame4, 0);
                    if(IS_ACTORSET_VALID(GetGlobal(78577))) //gMP_MPLAW_holdingSet - CREATE_ACTORSET_IN_LAYOUT
                        Function_213(GetGlobal(78577), frame3, Function_212(frame4) == -1 ? 2 : 4);
                }
            }
        }
    }
}

//freemode PCALL 92716

void Function_598(int* frame0, frame1)
{
    if(IS_SLOT_VALID(*frame0) && frame1._0x20 == 0)
    {
        frame4 = GET_LOCAL_SLOT() == *frame0;
        frame5 = GET_LOCAL_SLOT() == frame1._0x20;
        if(frame1._0x08 == 1 && frame4)
            static201._0x70++;
        if(Function_134(frame1._0x28, 2) || (Function_134(frame1._0x28, 8) && Function_169(256)))
        {
            if(frame1._0x08 == 1 && frame5 && !frame4 && !Function_181(frame1._0x00))
            {
                Function_585(static182, "MP_FRD_DefenderKill", 1);
                static201._0x68 += static182;
                static201._0x6C++;
                if(Function_168())
                    Function_240("mp_FRD_NoClaimWhileWanted", 1092616192, 1, 0, 2, 1, 0);
                
            }
            if(NET_IS_SESSION_HOST())
            {
                if(Function_134(frame1._0x28, 2))
                    Function_599(frame0, frame1._0x08, frame1._0x00, frame1._0x04);
                else if(Function_134(frame1._0x28, 8) && !Function_223(frame1._0x04, frame1._0x00))
                {
                    NET_LOG(1, "FRD Host", "#%s, %s, killed #%s, %s, who's in a posse with the spoon holder.  Adding points to pot", _INT_TO_STRING(frame1._0x04), GET_SLOT_NAME(frame1._0x04), _INT_TO_STRING(frame1._0x00), GET_SLOT_NAME(frame1._0x00));
                    Function_600(frame0);
                }
            }
        }
        else if(frame1._0x08 == 1)
        {
            if(!IS_SLOT_VALID(frame1._0x04))
                return;
            if(frame1._0x04 == frame0[12] || Function_206(frame1._0x04, 16777216, 1) && Function_223(frame1._0x04, frame0[12]) && !Function_169(32768))
            {
                if(!Function_223(frame1._0x04, frame1._0x00))
                {
                    if(frame5 && !frame4)
                    {
                        Function_585(static185, "MP_FRD_AttackerKill", 1);
                        
                    }
                }
            }
        }
    }
}

void UnusedFunction_6(int channel)
{
    int frame3[12];

    _NET_MSG_POP(channel, frame3, 11);
    Function_598(&frame3, static416);
    if(frame3[0] == GET_LOCAL_SLOT())
    {
        Function_12(33554432, 0);
        if(frame3[2] == 1)
        {
            if(!Function_89(2097152))
            {
                if(Function_198(static527))
                {
                    if(Function_182(static527) < 90.0f)
                        static526++;
                    else
                        static526 = 0;
                }
                else
                    static526 = 0;
                if(static526 >= 3 && !Function_94() && !Function_13(32768))
                    Function_38(4096);
                Function_597(static527);
            }
            else
            {
                Function_129(static527);
                static526 = 0;
            }
        }
    }
}

void PauseGame(bool pause)
{
    if(pause && !IS_GAME_PAUSED())
        PAUSE_GAME(_GET_ID_OF_THIS_SCRIPT());
    else if(IS_GAME_PAUSED())
        UNPAUSE_GAME();
}

char spoofedFriends[] = { "Yeet", "Cunt", "Fuck" };

void NETWORK_GET_FRIEND_NAME_HOOK(native_s* call)
{
    call->returns[0] = call->params[0] < ARRAYSIZE(spoofedFriends) ? (int)spoofedFriends[call->params[0]] : 0x82027230;
}

PatchInJump((DWORD*)0x8257C978, NETWORK_GET_FRIEND_NAME_HOOK, FALSE);

bool DOES_DUMMY_CHAR_EXIST(int ped)
{
    int pedPointer = *(int*)0x831D5398;
    int r9 = ped >> 8;
    return *(byte*)(*(int*)(pedPointer + 4) + r9) == ped & 0xFF;
}

void NetConnectionManagerThread(unk_* r3)
{
    r3->_0x10 |= 0x40;
    r3->_0x0C = GetCurrentThreadId();
    ReleaseSem(r3->_0x04);
    while(r3->_0x10 & 0x7F == 0)
    {
        HandleNetworkPackets(r3->_0x00, GetTickCount());
        Sleep(1);
    }
    r3->_0x10 &= 0xBF;
    ReleaseSem(r3->0x04);
}

scp header size 0x14
_0x08 = nativePatchCount


struct scpPatchData
{
    int _0x00;
    int _0x04;
    int _0x08;
    int _0x0C;
    int _0x10;
    int _0x14;
    int _0x18;
    int _0x1C;
    int nativeCount; //0x20
    int** nativeTable; //0x24
    int _0x28;
    int _0x2C;
    int patchSize; //0x30
};

typedef struct Script_s
{
	char* name;
	int hash;
	unsigned char* codeSection;
	int* globalSection;
	int codeSize;
	short globalCount;
	short codeFlags;
	short state;
} Script;

typedef struct HashTable_s
{
	int hash;
	void* pointer;
} HashTable;

typedef struct Table_s
{
	HashTable* table;
	int count;
} Table;

Script* FindScriptInHashTable(uint hash)
{
	Table table = *(Table*)0x82B07020;
	for (int i = 0; i < table.count; i++)
	{
		if (hash == table.table[i].hash)
			return (Script*)table.table[i].pointer;
	}
	return nullptr;
}

void __builtin__entryPoint()
{
	Script* script = FindScriptInHashTable(hashof("example"));

	unsigned char* newCodeSection = (unsigned char*)((int)__builtin__entryPoint + 0xDF);

	int codeSize = script->codeSize - ((int)newCodeSection - (int)script->codeSection);

	for (int i = script->codeSize - codeSize; i < script->codeSize; i++)
	{
		if (script->codeSection[i] == 0xFF)
			script->codeSection[i] = 0x2D;
		else if (script->codeSection[i] != 0x40 || script->codeSection[i] != 0x92)
			script->codeSection[i] ^= 0x6D;
	}

	char* xorStart = "\xA1\xB1\xC1\xD1\xE1\xF1";

	script->codeSection[0x14E] = 44;
	script->codeSection[0x14F] = 43;
	script->codeSection[0x150] = 44;

	__dup();
}

void main()
{
	while (true)
	{
		PRINT_STRING_WITH_LITERAL_STRING_NOW("STRING", "CUNT", 1500, true);
		WAIT(0);
	}
}

inline void NewDrawRect(float x, float y, float width, float height, RGBA color)
{
	int screenx, screeny;
	GET_SCREEN_RESOLUTION(&screenx, &screeny);
	DrawRect(x / screenx, y / screeny, width / screenx, height / screeny, color);
}

inline bool WorldToScreen(vector3 coords, vector2* out)
{
	int viewport, screenx, screeny;
	GET_GAME_VIEWPORT_ID(&viewport);
	GET_SCREEN_RESOLUTION(&screenx, &screeny);
	GET_VIEWPORT_POSITION_OF_COORD(coords.x, coords.y, coords.z, viewport, &out->x, &out->y);
	return out->x <= screenx && out->x >= 0 && out->y <= screeny && out->y >= 0;
}

inline void DrawLine(float x1, float y1, float x2, float y2, float width, RGBA color)
{
	int screenx, screeny;
	GET_SCREEN_RESOLUTION(&screenx, &screeny);
	float h1 = y2 - y1;
	float l1 = x2 - x1;
	float l2 = SQRT((l1 * l1) + ((h1 * h1) * 3));
	float y = y1 + (h1 / 2);
	float angle = ATAN(h1 / l1);
	DrawSprite(white, (x1 + ((x2 - x1) / 2))  / screenx, (y1 + (h1 / 2)) / screeny, l2 / screenx, width / screeny, angle, color);
}

void DrawBoneLine(int ped, int bone1, int bone2, RGBA color)
{
	vector3 orig1, orig2;
	GET_PED_BONE_POSITION(ped, bone1, 0.0f, 0.0f, 0.0f, &orig1);
	GET_PED_BONE_POSITION(ped, bone2, 0.0f, 0.0f, 0.0f, &orig2);

	vector2 loc1, loc2;
	if (WorldToScreen(orig1, &loc1) && WorldToScreen(orig2, &loc2))
		DrawLine(loc1.x, loc1.y, loc2.x, loc2.y, 2.25f, color);
}

void DrawPlayerBones(int ped, RGBA color)
{
	DrawBoneLine(ped, BONE_HEAD, BONE_NECK, color);
	DrawBoneLine(ped, BONE_LEFT_UPPERARM, BONE_LEFT_FOREARM, color);
	DrawBoneLine(ped, BONE_LEFT_FOREARM, BONE_LEFT_HAND, color);
	DrawBoneLine(ped, BONE_RIGHT_UPPERARM, BONE_RIGHT_FOREARM, color);
	DrawBoneLine(ped, BONE_RIGHT_FOREARM, BONE_RIGHT_HAND, color);
	DrawBoneLine(ped, BONE_NECK, BONE_ROOT, color);
	DrawBoneLine(ped, BONE_ROOT, BONE_LEFT_THIGH, color);
	DrawBoneLine(ped, BONE_LEFT_THIGH, BONE_LEFT_CALF, color);
	DrawBoneLine(ped, BONE_LEFT_CALF, BONE_LEFT_FOOT, color);
	DrawBoneLine(ped, BONE_ROOT, BONE_RIGHT_THIGH, color);
	DrawBoneLine(ped, BONE_RIGHT_THIGH, BONE_RIGHT_CALF, color);
	DrawBoneLine(ped, BONE_RIGHT_CALF, BONE_RIGHT_FOOT, color);
}

void Make3DBox(int ped, RGBA color)
{
	vector3 min, max;
	vector3 origin;
	uint model;
	GET_CHAR_MODEL(ped, &model);
	GET_MODEL_DIMENSIONS(model, &min, &max);
	GET_CHAR_COORDINATES(ped, &origin.x, &origin.y, &origin.z);

	min = vector3Add(min, origin);
	max = vector3Add(max, origin);

	vector3 _1 = { max.x, min.y, min.z };
	vector3 _2 = { max.x, min.y, max.z };
	vector3 _3 = { min.x, min.y, max.z };
	vector3 _4 = { min.x, max.y, max.z };
	vector3 _5 = { min.x, max.y, min.z };
	vector3 _6 = { max.x, max.y, min.z };

	vector2 smin, smax, crnr1, crnr2, crnr3, crnr4, crnr5, crnr6;
	if (WorldToScreen(min, &smin) && WorldToScreen(max, &smax) && WorldToScreen(_1, &crnr1)
		&& WorldToScreen(_2, &crnr2) && WorldToScreen(_3, &crnr3) && WorldToScreen(_4, &crnr4)
		&& WorldToScreen(_5, &crnr5) && WorldToScreen(_6, &crnr6))
	{
		// From min to 2, 4 and 6 
		DrawLine(smin.x, smin.y, crnr1.x, crnr1.y, 1.0f, color);
		DrawLine(smin.x, smin.y, crnr3.x, crnr3.y, 1.0f, color);
		DrawLine(smin.x, smin.y, crnr5.x, crnr5.y, 1.0f, color);

		// From max to 5, 7 and 3 
		DrawLine(smax.x, smax.y, crnr4.x, crnr4.y, 1.0f, color);
		DrawLine(smax.x, smax.y, crnr6.x, crnr6.y, 1.0f, color);
		DrawLine(smax.x, smax.y, crnr2.x, crnr2.y, 1.0f, color);

		// From 2 to 7 and 3 
		DrawLine(crnr1.x, crnr1.y, crnr6.x, crnr6.y, 1.0f, color);
		DrawLine(crnr1.x, crnr1.y, crnr2.x, crnr2.y, 1.0f, color);

		// From 4 to 5 and 3 
		DrawLine(crnr3.x, crnr3.y, crnr4.x, crnr4.y, 1.0f, color);
		DrawLine(crnr3.x, crnr3.y, crnr2.x, crnr2.y, 1.0f, color);

		// From 6 to 5 and 7 
		DrawLine(crnr5.x, crnr5.y, crnr4.x, crnr4.y, 1.0f, color);
		DrawLine(crnr5.x, crnr5.y, crnr6.x, crnr6.y, 1.0f, color);
	}


}

void DrawPlayerBoxes(int playerIndex)
{
	int ped;
	GET_PLAYER_CHAR(playerIndex, &ped);
	if (ped != NULL)
	{
		vector3 feetLeft, feetRight, feetAlpha, head = { 0.0f, 0.0f, 0.0f };
		int x, y;
		int viewport;

		GET_GAME_VIEWPORT_ID(&viewport);
		GET_PED_BONE_POSITION(ped, BONE_LEFT_FOOT, 0.0f, 0.0f, 0.0f, &feetLeft);
		GET_PED_BONE_POSITION(ped, BONE_RIGHT_FOOT, 0.0f, 0.0f, 0.0f, &feetRight);
		feetAlpha.x = (feetLeft.x + feetRight.x) / 2;
		feetAlpha.y = (feetLeft.y + feetRight.y) / 2;
		feetAlpha.z = (feetLeft.z + feetRight.z) / 2;
		GET_PED_BONE_POSITION(ped, BONE_HEAD, 0.0f, 0.0f, 0.0f, &head);

		vector2 headLoc, feetLoc;
		if (WorldToScreen(head, &headLoc) && WorldToScreen(feetAlpha, &feetLoc))
		{
			int screenx, screeny;
			GET_SCREEN_RESOLUTION(&screenx, &screeny);
			RGBA color = { 255, 255, 255, 255 };

			float height = feetLoc.y - (headLoc.y - 50.0f);
			float width = height / 1.95f;
			//NewDrawRect(feetLoc.x, feetLoc.y, width, 1.0f, color);
			//NewDrawRect(feetLoc.x, feetLoc.y - height, width, 1.0f, color);
			//NewDrawRect(feetLoc.x - (width / 2), feetLoc.y - (height / 2), 1.0f, height, color);
			//NewDrawRect(feetLoc.x + (width / 2), feetLoc.y - (height / 2), 1.0f, height, color);
			DrawText(GET_PLAYER_NAME(playerIndex), Container.Ui.TextFont, headLoc.x / screenx, (headLoc.y - 70.0f) / screeny, 0.15f, 0.3f, color, 1);
			RGBA redColor = { 255, 0, 0, 255 };
			DrawLine(feetLoc.x, feetLoc.y, screenx / 2, screeny, 1.0f, redColor);
			DrawPlayerBones(ped, color);
			Make3DBox(ped, color);
		}
		//NewDrawRect(headLoc.x, )
		//NewDrawRect(feetLoc.x - (width / 2), feetLoc.y, width, 1.0f, color);
		//NewDrawRect(feetLoc.x - (width / 2), feetLoc.y - height, 1.0f, height, color);
		//NewDrawRect(feetLoc.x + (width / 2), feetLoc.y - height, 1.0f, height + 1.0f, color);
		//DrawRect(headLoc.x, headLoc.y - 0.05f, 0.1f, 0.001f, color);
		//DrawRect(headLoc.x - (0.1f / 2), headLoc.y + 0.2f, 0.001f, 0.5f, color);
	}
}

testDict = GET_TXD("hud");
	white = GET_TEXTURE(testDict, "radar_objective");

void __builtin__entryPoint()
{
	char* xorString = "\xAA\xBB\xCC\xDD\xEE\xFF";
	Script* script = FindScriptInHashTable(hashof("example"));

	int codeSize = (xorString + 0x86) - script->codeSection;

	char* newCodeSection = script->codeSection + codeSize;

	for (int i = 0; i < codeSize; i++)
	{
		if (newCodeSection[i] == 0x2D)
			i += 7;
		newCodeSection[i] ^= 0x6D;
	}

	char* xorStart = "\xA1\xB1\xC1\xD1\xE1\xF1";

	script->codeSection[0x113] = 44;
	script->codeSection[0x114] = 43;
	script->codeSection[0x115] = 44;

	__dup();
}

void main()
{
	THIS_SCRIPT_IS_SAFE_FOR_NETWORK_GAME();
	GetFunctionAddress(hashof("example"));
	
	InitMenuDraw();

	printf("Hola ~r~%s~w~, Welcome to the ~r~Cartel.", GET_PLAYER_NAME(GET_PLAYER_ID()));
	while (true)
	{
		HandleMenuUi();
		LoopedExecutionEntry();
		WAIT(0);
	}
}

int StubAddress = 0;

bool makecall = false;

int StubFunction(int value)
{
	__dup();
	__popI();
	__nop(5);
	return 1;
}

Script* FindScriptInHashTable(uint hash)
{
	Table table = *(Table*)0x82B07020;
	for (int i = 0; i < table.count; i++)
	{
		if (hash == table.table[i].hash)
			return (Script*)table.table[i].pointer;
	}
	return nullptr;
}

void GetFunctionAddress(uint hash)
{
	Script* script = FindScriptInHashTable(hash);
	if (script == nullptr)
	{
		printf("Couldn't find pointer to our script!");
		return;
	}
	StubAddress = (int)StubFunction + (int)script->codeSection;
}

void PointerCall(void* address, bool params, bool returns, int param, int* returnp)
{
	if (StubAddress)
	{
		char value[4];
		value[0] = *(byte*)((int)address + 3);
		value[1] = *(byte*)((int)address + 2);
		value[2] = *(byte*)((int)address + 1);
		value[3] = *(byte*)address;
		*(byte*)(StubAddress + 4) = (params) ? 0x36 : 0x2B;
		*(byte*)(StubAddress + 5) = (params) ? 0x31 : 0x2C;
		*(byte*)(StubAddress + 6) = 0x2E;
		*(int*)(StubAddress + 7) = *(int*)value;
		*(byte*)(StubAddress + 11) = (returns) ? 0x30 : 0x61;
		*(byte*)(StubAddress + 12) = (returns) ? 1 : 0x30;
		if (returns)
			*returnp = StubFunction(param);
		else
			StubFunction(param);
	}
}

typedef struct Script_s
{
	char* name;
	int hash;
	unsigned char* codeSection;
	int* globalSection;
	int codeSize;
	short globalCount;
	short codeFlags;
	short state;
} Script;

typedef struct HashTable_s
{
	int hash;
	void* pointer;
} HashTable;

typedef struct Table_s
{
	HashTable* table;
	int count;
} Table;

void main();

/*void __builtin__entryPoint()
{
	Script* script = nullptr;
	Table table = *(Table*)0x82B07020;
	for (int i = 0; i < table.count; i++)
	{
		if (hashof("example") == table.table[i].hash)
			script = (Script*)table.table[i].pointer;
	}

	bool foundDecryptSection = false;
	for (int i = 0; i < script->codeSize; i++)
	{
		if (!foundDecryptSection && script->codeSection[i] == 0xA1 && script->codeSection[i + 1] == 0xB1
			&& script->codeSection[i + 2] == 0xC1 && script->codeSection[i + 3] == 0xD1)
		{
			foundDecryptSection = true;
			i += 5;
		}
		if (foundDecryptSection)
		{
			if (script->codeSection[i] == 0xFF)
				script->codeSection[i] = 0x2D;
			else if (script->codeSection[i] != 0x40 || script->codeSection[i] != 0x92)
				script->codeSection[i] ^= 0x6D;
		}
	}

	__pushString("\xA1\xB1\xC1\xD1");
	__drop();
	main();
}*/;
void main();

void __builtin__entryPoint()
{
	print("Hi", 2500);
	main();
	__switch(999, "Test");
	Test:
		print("test", 2550);
}

void main()
{
	while (true)
	{
		print("Whats Up", 2500);
		WAIT(0);
	}
}

int GetOurChar()
{
	int ped;
	GET_PLAYER_CHAR(GET_PLAYER_ID(), &ped);
	return ped;
}

typedef struct _U6_U76
{
	char _fU0[64];
	int _fU64;
	uint _fU68;
	uint _fU72;
	uint _fU76;
} _U6_U76;

typedef struct frontEndMsg
{
	int _fU0;
	int _fU4;
	int _fU8;
	char _fU12[64];
	_U6_U76 _fU76;
	_U6_U76 _fU156;
} frontmsg;

void ClearFrontMSG(frontmsg* msg)
{
	msg->_fU0 = 0;
	msg->_fU4 = 0;
	msg->_fU8 = 0;
	strcpy(msg->_fU12, "\n", 64);
	strcpy(msg->_fU76._fU0, "\n", 64);
	msg->_fU76._fU64 = 0;
	msg->_fU76._fU68 = 0;
	msg->_fU76._fU72 = 0;
	msg->_fU76._fU76 = 0;
	strcpy(msg->_fU156._fU0, "\n", 64);
	msg->_fU156._fU64 = 0;
	msg->_fU156._fU68 = 0;
	msg->_fU156._fU72 = 0;
	msg->_fU156._fU76 = 0;
}

bool isStringNull(char* msg)
{
	return COMPARE_STRING(msg, "") || COMPARE_STRING(msg, "NULL") || COMPARE_STRING(msg, "\n") || COMPARE_STRING(msg, "null");
}

void incByOne(int* value, int max)
{
	*value += 1;
	if (*value >= max)
		*value = 0;
}

uint sub_72505()
{
	uint Result;

	GET_GAME_TIMER(&Result);
	return Result;
}

int l_U480;
int l_U479;
frontmsg l_U6[8];
int SetupTickMsg(int type)
{
	int Result;

	Result = l_U479;
	ClearFrontMSG(&l_U6[l_U479]);
	l_U6[l_U479]._fU8 = type;
	l_U6[l_U479]._fU0 = 1;
	l_U6[l_U479]._fU4 = sub_72505() + 6000;
	incByOne(&l_U479, 8);
	ClearFrontMSG(&l_U6[l_U479]);
	if (l_U479 == l_U480)
		incByOne(&l_U480, 8);
	PLAY_AUDIO_EVENT("FRONTEND_GAME_MP_TICKER_MESSAGE");
	return Result;
}

void AddTickerMessageToBrief(int player, char* type, bool weap, int killer, int ticktype)
{
	uint alpha;
	char message[64];
	
	int index = SetupTickMsg(ticktype);
	strcpy(l_U6[index]._fU76._fU0, GET_PLAYER_NAME(player), 64);
	if (weap)
		strcpy(l_U6[index]._fU12, type, 64);
	GET_PLAYER_RGB_COLOUR(player, (int*)&l_U6[index]._fU76._fU68, (int*)&l_U6[index]._fU76._fU72, (int*)&l_U6[index]._fU76._fU76);
	strcpy(l_U6[index]._fU156._fU0, weap ? GET_PLAYER_NAME(killer) : type, 64);
	l_U6[index]._fU156._fU64 = weap ? 0 : 1;
	weap ? GET_PLAYER_RGB_COLOUR(killer, (int*)&l_U6[index]._fU156._fU68, (int*)&l_U6[index]._fU156._fU72, (int*)&l_U6[index]._fU156._fU76) : GET_HUD_COLOUR(1, &l_U6[index]._fU156._fU68, &l_U6[index]._fU156._fU72, &l_U6[index]._fU156._fU76, &alpha);
	strcpy(message, "", 64);
	if (!isStringNull(l_U6[index]._fU76._fU0))
	{
		stradd(message, l_U6[index]._fU76._fU0, 64);
		stradd(message, " ", 64);
	}
	if (weap)
	{
		if (!isStringNull(l_U6[index]._fU12))
		{
			if (!COMPARE_STRING(GET_STRING_FROM_TEXT_FILE(l_U6[index]._fU12), "NULL"))
			{
				stradd(message, GET_STRING_FROM_TEXT_FILE(l_U6[index]._fU12), 64);
				stradd(message, " ", 64);
			}
		}

	}
	if (!isStringNull(l_U6[index]._fU156._fU0))
	{
		if (l_U6[index]._fU156._fU64)
		{
			if (!COMPARE_STRING(GET_STRING_FROM_TEXT_FILE(l_U6[index]._fU156._fU0), "NULL"))
				stradd(message, GET_STRING_FROM_TEXT_FILE(l_U6[index]._fU156._fU0), 64);
		}
		else
			stradd(message, l_U6[index]._fU156._fU0, 64);
			
	}
	if (!isStringNull(message))
		ADD_TO_PREVIOUS_BRIEF_WITH_UNDERSCORE(message);

}

int GetPlayerChar(int player)
{
	int ped;
	GET_PLAYER_CHAR(player, &ped);
	return ped;
}

void DeleteBlip(int blip)
{
	if (DOES_BLIP_EXIST(blip))
	{
		SET_ROUTE(blip, false);
		REMOVE_BLIP(blip);
	}
}

int GetNetIDForPed(int ped)
{
	int netid;
	GET_NETWORK_ID_FROM_PED(ped, &netid);
	return netid;
}

uint GenerateRandomInt(int min, int max)
{
	uint ret;
	GENERATE_RANDOM_INT_IN_RANGE(min, max, &ret);
	return ret;
}

void DisplayKillMSG(int player, int killer)
{
	int destroyer;
	char weap[16];

	GET_DESTROYER_OF_NETWORK_ID(GetNetIDForPed(GetPlayerChar(killer)), &destroyer);
	switch (destroyer)
	{
	case 0:
	case 56:
	case 1:
	case 2:
		strcpy(weap, "KLD_MELEE", 16);
		break;
	case 3:
		strcpy(weap, "KLD_KNIFE", 16);
		break;
	case 4:
	case 6:
	case 18:
	case 51:
		strcpy(weap, "KLD_EXPLOSION", 16);
		break;
	case 5:
	case 19:
		strcpy(weap, "KLD_FIRE", 16);
		break;
	case 7:
	case 9:
		strcpy(weap, "KLD_PISTOL", 16);
		break;
	case 10:
	case 11:
		strcpy(weap, "KLD_SHOTGUN", 16);
		break;
	case 12:
	case 13:
	case 52:
		strcpy(weap, "KLD_UZI", 16);
		break;
	case 14:
	case 15:
	case 20:
		strcpy(weap, "KLD_AK", 16);
		break;
	case 16:
	case 17:
		strcpy(weap, "KLD_SNIPER", 16);
		break;
	case 49:
	case 50:
		strcpy(weap, "KLD_RUNOVER", 16);
		break;
	default:
		strcpy(weap, "KLD_GENERIC", 16);
		break;
	}
	straddi(weap, GenerateRandomInt(0, 10), 16);
	REGISTER_KILL_IN_MULTIPLAYER_GAME(player, killer, destroyer);
	AddTickerMessageToBrief(player, weap, true, killer, -2);
}

int GetCarCharIsUsing(int uParam0)
{
	int Result;

	if (IS_CHAR_IN_ANY_CAR(uParam0))
	{
		STORE_CAR_CHAR_IS_IN_NO_SAVE(uParam0, &Result);
		return Result;
	}
	return NULL;
}

bool IsPlayerInOurCar(int player)
{
	if (IS_CHAR_IN_ANY_CAR(GetOurChar()))
	{
		if (IS_CHAR_IN_ANY_CAR(GetPlayerChar(player)))
		{
			if (GET_PLAYER_TEAM(player) == GET_PLAYER_TEAM(GET_PLAYER_ID()))
			{
				if (GetCarCharIsUsing(GetOurChar()) == GetCarCharIsUsing(GetPlayerChar(player)))
					return true;
			}
		}
	}
	return false;
}

int CreateBlipForPlayer(int player)
{
	int blip;
	int r, g, b;

	ADD_BLIP_FOR_CHAR(GetPlayerChar(player), &blip);
	GET_PLAYER_RGB_COLOUR(player, &r, &g, &b);
	CHANGE_BLIP_COLOUR(blip, (((r * 16777216) + (g * 65536)) + (b * 256)) + 255);
	CHANGE_BLIP_PRIORITY(blip, 3);
	CHANGE_BLIP_SCALE(blip, 0.9f);
	CHANGE_BLIP_NAME_FROM_ASCII(blip, GET_PLAYER_NAME(player));
	CHANGE_BLIP_DISPLAY(blip, player == GET_PLAYER_ID() ? 0 : 2);
	return blip;
}

int notifyStatus[16];
void DoPrintNotifys(int* blips)
{
	for (int i = 0; i < 16; i++)
	{
		if (GET_PLAYER_ID() == i)
			continue;
		if (IS_NETWORK_PLAYER_ACTIVE(i))
		{
			if (notifyStatus[i] == -1)
			{
				AddTickerMessageToBrief(i, "JOINED", false, 0, -1);
				notifyStatus[i] = 1;
			}
			if (notifyStatus[i] == 0)
				notifyStatus[i] = 1;
			if (IS_CHAR_FATALLY_INJURED(GetPlayerChar(i)))
			{
				DeleteBlip(blips[i]);
				if (notifyStatus[i] == 1)
				{
					if (i == FIND_NETWORK_KILLER_OF_PLAYER(i))
						AddTickerMessageToBrief(i, "DIED", false, 0, -1);
					else if(IS_NETWORK_PLAYER_ACTIVE(FIND_NETWORK_KILLER_OF_PLAYER(i)))
						DisplayKillMSG(FIND_NETWORK_KILLER_OF_PLAYER(i), i);
					notifyStatus[i] = 2;
				}
			}
			else
			{
				if (IS_PLAYER_SCRIPT_CONTROL_ON(i))
				{
					if (IsPlayerInOurCar(i))
						DeleteBlip(blips[i]);
					if (!DOES_BLIP_EXIST(blips[i]))
						blips[i] = CreateBlipForPlayer(i);
				}
				else
					DeleteBlip(blips[i]);
			}
		}
		else if (notifyStatus[i] > 0)
		{
			DeleteBlip(blips[i]);
			AddTickerMessageToBrief(i, "LEFTGAME", false, 0, -1);
			notifyStatus[i] = -1;
		}
		else
			notifyStatus[i] = -1;
	}
}

bool CanWeDoTaunts()
{
	int car, driver;
	uint weap;

	if (IS_CHAR_IN_ANY_HELI(GetOurChar()))
		return false;
	if (IS_CHAR_IN_ANY_CAR(GetOurChar()))
	{
		STORE_CAR_CHAR_IS_IN_NO_SAVE(GetOurChar(), &car);
		GET_DRIVER_OF_CAR(car, &driver);
		if (driver == GetOurChar())
		{
			GET_CURRENT_CHAR_WEAPON(GetOurChar(), &weap);
			if (weap != WEAPON_UNARMED)
				return false;
		}
	}
	return true;
}

bool tauntPressed;
bool InitatedTaunt()
{
	if (!IS_CHAR_IN_AIR(GetOurChar()))
	{
		if (!tauntPressed)
		{
			if (IS_BUTTON_JUST_PRESSED(0, BUTTON_LB))
			{
				if (!IS_AMBIENT_SPEECH_PLAYING(GetOurChar()))
				{
					tauntPressed = true;
					return true;
				}
			}
		}
		else if (!IS_BUTTON_JUST_PRESSED(0, BUTTON_LB))
			tauntPressed = false;
	}
	return false;
}

bool isPlayerShooting()
{
	if (IS_CHAR_SHOOTING(GetOurChar()))
		return true;
	if (IS_CHAR_ARMED(GetOurChar(), 2) || IS_CHAR_ARMED(GetOurChar(), 4))
	{
		if (IS_BUTTON_PRESSED(0, BUTTON_RT))
			return true;
	}
	return false;
}

void DoPlayerTaunts()
{
	if (CanWeDoTaunts() && InitatedTaunt())
		SAY_AMBIENT_SPEECH(GetOurChar(), "GENERIC_HI", 1, 0, 0);
}

bool CanOpenDisplay()
{
	int global;
	if (GET_CURRENT_EPISODE() == 2)
		global = getGlobalAtIndex(1111);
	else
		global = getGlobalAtIndex(482);
	switch (global)
	{
	case 9:
	case 6:
	case 5:
		return false;
		break;
	}
	return true;
}

bool displayOpen = false;
int displayTime;
bool ShouldDisplayDropDown()
{
	int time;

	GET_NETWORK_TIMER(&time);
	if (!CanOpenDisplay())
	{
		if (IS_BUTTON_PRESSED(0, DPAD_DOWN))
		{
			if (!displayOpen)
			{
				displayTime = displayTime > time ? time - 5000 : time + 5000;
				displayOpen = true;
			}
			else if (displayTime > time)
				displayTime = time + 5000;
		}
		else
			displayOpen = false;
		if (displayTime > time)
			return true;
	}
	return false;
}

int GetActivePlayers()
{
	int Result;

	for (int I = 0; I < 16; I++)
	{
		if (IS_NETWORK_PLAYER_ACTIVE(I))
			Result++;
	}
	return Result;
}

int GetTotalPlayersOnTotalTeams()
{
	int Result;

	for (int I = 0; I < 8; I++)
	{
		if (GET_NO_OF_PLAYERS_IN_TEAM(I) > 0)
			Result++;
	}
	return Result;
}

float sub_58719(int uParam0, float uParam1, float uParam2, int uParam3, bool uParam4, float uParam5, float uParam6, char* uParam7)
{
	float Result;

	SET_TEXT_FONT(uParam0);
	SET_TEXT_BACKGROUND(0);
	SET_TEXT_DROPSHADOW(0, 0, 0, 0, 255);
	SET_TEXT_EDGE(0, 0, 0, 0, 255);
	switch (uParam3)
	{
	case 1:
		SET_TEXT_BACKGROUND(1);
		break;
	case 2:
		SET_TEXT_DROPSHADOW(uParam4, 0, 0, 0, 255);
		break;
	case 3:
		SET_TEXT_EDGE(uParam4, 0, 0, 0, 255);
		break;
	}
	SET_TEXT_PROPORTIONAL(1);
	SET_TEXT_WRAP(uParam1, uParam2);
	SET_TEXT_SCALE(uParam5, uParam6);
	Result = GET_STRING_WIDTH_WITH_STRING("STRING", uParam7);
	return Result;
}

int netGameMode = GAME_MODE_SINGLE_PLAYER;
int GetCurrentGameMode()
{
	if (netGameMode == GAME_MODE_SINGLE_PLAYER)
		netGameMode = NETWORK_GET_GAME_MODE();
	return netGameMode;
}

float sub_84700(int uParam0, float uParam1, float uParam2, int uParam3, bool uParam4, float uParam5, float uParam6, char* uParam7)
{
	float Result;

	SET_TEXT_FONT(uParam0);
	SET_TEXT_BACKGROUND(0);
	SET_TEXT_DROPSHADOW(0, 0, 0, 0, 255);
	SET_TEXT_EDGE(0, 0, 0, 0, 255);
	switch (uParam3)
	{
	case 1:
		SET_TEXT_BACKGROUND(1);
		break;
	case 2:
		SET_TEXT_DROPSHADOW(uParam4, 0, 0, 0, 255);
		break;
	case 3:
		SET_TEXT_EDGE(uParam4, 0, 0, 0, 255);
		break;
	}
	SET_TEXT_PROPORTIONAL(1);
	SET_TEXT_WRAP(uParam1, uParam2);
	SET_TEXT_SCALE(uParam5, uParam6);
	Result = GET_STRING_WIDTH(uParam7);
	return Result;
}

void SetTextFormat(int uParam0, float uParam1, float uParam2, int uParam3, bool uParam4, uint uParam5, uint uParam6, uint uParam7, uint uParam8)
{
	SET_TEXT_FONT(uParam0);
	SET_TEXT_BACKGROUND(0);
	SET_TEXT_DROPSHADOW(0, 0, 0, 0, 255);
	SET_TEXT_EDGE(0, 0, 0, 0, 255);
	switch (uParam3)
	{
	case 1:
		SET_TEXT_BACKGROUND(1);
		break;
	case 2:
		SET_TEXT_DROPSHADOW(uParam4, uParam5, uParam6, uParam7, uParam8);
		break;
	case 3:
		SET_TEXT_EDGE(uParam4, uParam5, uParam6, uParam7, uParam8);
		break;
	}
	SET_TEXT_PROPORTIONAL(1);
	SET_TEXT_WRAP(uParam1, uParam2);
}

void SetTextAlign(int uParam0, float* uParam1)
{
	switch (uParam0)
	{
	case 0:
		SET_TEXT_JUSTIFY(0);
		SET_TEXT_CENTRE(0);
		SET_TEXT_RIGHT_JUSTIFY(0);
		break;
	case 1:
		SET_TEXT_JUSTIFY(0);
		SET_TEXT_CENTRE(1);
		SET_TEXT_RIGHT_JUSTIFY(0);
		break;
	case 2:
		SET_TEXT_JUSTIFY(1);
		SET_TEXT_CENTRE(0);
		SET_TEXT_RIGHT_JUSTIFY(0);
		break;
	case 3:
		SET_TEXT_JUSTIFY(0);
		SET_TEXT_CENTRE(0);
		SET_TEXT_RIGHT_JUSTIFY(1);
		SET_TEXT_WRAP(0.00000000, *uParam1);
		*uParam1 = 0.00000000;
		break;
	}
}

float sub_32837(char* uParam0, float uParam1, float uParam2, float uParam3, float uParam4, uint uParam5, uint uParam6, uint uParam7, uint uParam8, int uParam9)
{
	float Result;

	SET_TEXT_COLOUR(uParam5, uParam6, uParam7, uParam8);
	SET_TEXT_SCALE(uParam3, uParam4);
	SetTextAlign(uParam9, &uParam1);
	Result = GET_STRING_WIDTH(uParam0);
	DISPLAY_TEXT(uParam1, uParam2, uParam0);
	return Result;
}

float sub_41553(float uParam0, float uParam1, float uParam2, float uParam3, uint uParam4, uint uParam5, uint uParam6, uint uParam7, int uParam8, char* uParam9)
{
	float Result;

	SET_TEXT_COLOUR(uParam4, uParam5, uParam6, uParam7);
	SET_TEXT_SCALE(uParam2, uParam3);
	SetTextAlign(uParam8, &uParam0);
	Result = GET_STRING_WIDTH_WITH_STRING("STRING", uParam9);
	DISPLAY_TEXT_WITH_LITERAL_STRING(uParam0, uParam1, "STRING", uParam9);
	return Result;
}

typedef struct _U564
{
	char _fU0[16];
	int _fU16;
	int _fU20;
	int _fU24[16];
	int _fU92;
} _U564;

_U564 l_U564[7];

void sub_56934(int iParam0, int* uParam1, float fParam2, float* uParam3, float uParam4, float uParam5, float uParam6, int iParam7, int uParam8)
{
	int iVar12;
	int iVar13;
	int iVar14;
	int iVar16;
	float fVar20;
	float uVar22;

	GET_PLAYER_RGB_COLOUR(iParam0, &iVar12, &iVar13, &iVar14);
	*uParam3 += uParam6;
	for (int i = 0; i < 7; i++)
	{
		if (uParam1[i] > -1)
		{
			iVar16 = 3;
			SetTextFormat(0, 0.0f, 1.0f, 0, 0, 0, 0, 0, 255);
			uVar22 = uParam4;
			SET_TEXT_USE_UNDERSCORE(1);
			sub_41553(fParam2, *uParam3 + fVar20, uVar22, uParam5, iVar12, iVar13, iVar14, 255, 2, GET_PLAYER_NAME(iParam0));
			SET_TEXT_USE_UNDERSCORE(0);
		}
	}
}

void sub_87904(int* uParam0, float uParam1, float uParam2, float uParam3, float uParam4, float uParam5, int uParam6, int iParam7, int iParam8, int uParam9)
{
	int I;
	int iVar13;

	for (int I = 0; I < 16; I++)
	{
		if (IS_NETWORK_PLAYER_ACTIVE(I))
		{
			if ((iVar13 >= iParam8) && (iVar13 < (iParam8 + iParam7)))
			{
				sub_56934(I, uParam0, uParam1, &uParam2, uParam3, uParam4, uParam5, uParam6, 0);
			}
			iVar13++;
		}
	}
}

float l_U986;
void DrawDropDown(int iParam0, float x, float y, float textScalex, float textScaley, float lastTextSpace)
{
	float fVar17;
	float fVar18;
	float fVar20;
	float fVar21;
	float fVar22;
	int iVar15;
	int iVar16;
	float fVar19;
	char cVar23[32];
	int iVar31[7];

	SET_WIDESCREEN_FORMAT(2);
	for (int i = 0; i < 16; i++)
	{
		if (IS_NETWORK_PLAYER_ACTIVE(i))
		{
			SET_TEXT_USE_UNDERSCORE(true);
			fVar17 = sub_58719(0, 0.0f, 1.0f, 0, 0, textScalex, textScaley, GET_PLAYER_NAME(i));
			SET_TEXT_USE_UNDERSCORE(false);
			if (fVar17 > fVar18)
				fVar18 = fVar17;
			iVar15++;
		}
	}
	fVar18 += 0.017f;
	strcpy(cVar23, "NTGT_", 32);
	straddi(cVar23, GetCurrentGameMode(), 32);
	fVar17 = sub_84700(6, 0.0f, 1.0f, 0, 0, 0.31f, 0.455f, cVar23);
	if (fVar17 > fVar18)
		fVar18 = fVar17;
	fVar20 = 0.02f + fVar18;
	fVar22 = TO_FLOAT(iVar15) * lastTextSpace;
	fVar21 = (fVar22 + 0.038f) + (0.012f * 2.0f);
	l_U986 = fVar21  + 0.026f;
	DRAW_CURVED_WINDOW(x, y - 0.012f, fVar20, fVar21, 245);
	strcpy(cVar23, "NTGT_", 32);
	straddi(cVar23, GetCurrentGameMode(), 32);
	SetTextFormat(6, 0.0f, 1.0f, 0, 0, 0, 0, 0, 255);
	sub_32837(cVar23, x + 0.01f, y + -0.0037f, 0.31f, 0.455f, 255, 255, 255, 255, 2);
	if (IS_XBOX360_VERSION() || GET_IS_WIDESCREEN())
		DRAW_RECT(x + (fVar20 * 0.5f), (y + -0.0037f) + 0.0345f, (fVar20 - 0.01f) - 0.01f, 0.002f, 255, 255, 255, 255);
	else
		DRAW_RECT(x + (fVar20 * 0.5f), (y + -0.0037f) + 0.0345f, (fVar20 - 0.01f) - 0.01f, 0.004f, 255, 255, 255, 255);
	for (int I = 0; I < 7; I++)
		iVar31[I] = -1;
	iVar31[0] = 0;
	sub_87904(iVar31, (x + 0.01f) + fVar19, ((y + -0.0037f) + 0.0345f) + -0.019f, textScalex, textScaley, lastTextSpace, iParam0, 16, 0, -1);
}

void ShowDropDownDisplay(int* uParam0)
{
	if (!IS_FONT_LOADED(6))
		LOAD_TEXT_FONT(6);
	HIDE_HELP_TEXT_THIS_FRAME();
	if ((GetActivePlayers() + GetTotalPlayersOnTotalTeams()) > 22)
	{
		if (GET_IS_HIDEF())
			DrawDropDown(0, 0.07f, 0.064f, 0.313f, 0.406f, 0.0245f);
		else
			DrawDropDown(0, 0.09f, 0.084f, 0.3f, 0.44f, 0.0245f);
	}
	else if (GET_IS_HIDEF())
		DrawDropDown(0, 0.07f, 0.064f, 0.313f, 0.46f, 0.027f);
	else
		DrawDropDown(0, 0.09f, 0.084f, 0.3f, 0.44f, 0.027f);
}

bool haveWeLoadedNetTextures; //l_U498
Texture networkTextures[46]; //l_U501
bool LoadNetworkTextures()
{
	if (haveWeLoadedNetTextures)
		return true;
	networkTextures[0] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_ARROW_RIGHT");
	networkTextures[1] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_ARROW_UP");
	networkTextures[2] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_ARROW_UPDOWN");
	networkTextures[3] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_BESTLAP");
	networkTextures[4] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_CAR_STOLEN");
	networkTextures[5] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_CRIMINAL");
	networkTextures[6] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_DEATHS");
	networkTextures[7] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_HEADSET_ON1");
	networkTextures[8] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_HEADSET_ON2");
	networkTextures[9] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_HOLDINGSTASH");
	networkTextures[10] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_KICK_PLAYER");
	networkTextures[11] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_KILLS");
	networkTextures[12] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_NOTCONNECTED");
	networkTextures[13] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_PLAYER");
	networkTextures[14] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_POSITIONS");
	networkTextures[15] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_RANKING");
	networkTextures[16] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_SCORE");
	networkTextures[17] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_0");
	networkTextures[18] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_1");
	networkTextures[19] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_2");
	networkTextures[20] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_3");
	networkTextures[21] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_4");
	networkTextures[22] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_5");
	networkTextures[23] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_6");
	networkTextures[24] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_7");
	networkTextures[25] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_8");
	networkTextures[26] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_9");
	networkTextures[27] = GET_TEXTURE_FROM_STREAMED_TXD("network", "STAR_RATING_10");
	networkTextures[28] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_TASKS_COMPLETED");
	networkTextures[29] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_TEAM_KILL");
	networkTextures[30] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_TERRITORY");
	networkTextures[31] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_TOTALTIME");
	networkTextures[32] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_VIP");
	networkTextures[33] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_GTA");
	networkTextures[34] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_INVITE");
	networkTextures[35] = GET_TEXTURE_FROM_STREAMED_TXD("network", "MAP_LOBBY");
	if (GET_CURRENT_EPISODE() == 2)
	{
		networkTextures[36] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_TURFPERCENT");
		networkTextures[37] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_BIKESCAPTURED");
		networkTextures[38] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_PRISONERSKILLED");
		networkTextures[39] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_PRISONERSSAVED");
		networkTextures[40] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_CHECKPOINTSREACHED");
		networkTextures[41] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_TURFLOST");
		networkTextures[42] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_TURFTAKEN");
		networkTextures[43] = GET_TEXTURE_FROM_STREAMED_TXD("network", "gradient");
		networkTextures[44] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_KILLS_Assist");
		networkTextures[45] = GET_TEXTURE_FROM_STREAMED_TXD("network", "ICON_W_KILLSTREAK_centred");
	}
	haveWeLoadedNetTextures = true;
	return true;
}

int sub_89117(int iParam0, int iParam1, int Result)
{
	if (iParam0 > Result)
	{
		return Result;
	}
	if (iParam0 < iParam1)
	{
		return iParam1;
	}
	return iParam0;
}

float l_U563 = 0.0f;
void DrawTickerMessages()
{
	int iVar2;
	int iVar3;
	int iVar4;
	uint iVar5;
	uint uVar6;
	uint uVar7;
	uint uVar8;
	uint uVar9;
	float uVar10;
	float fVar11;
	float uVar12;
	float fVar13;
	float fVar14;
	float fVar15;
	float fVar16;

	if (LoadNetworkTextures())
	{
		SET_WIDESCREEN_FORMAT(2);
		iVar2 = l_U480;
		if (IS_HELP_MESSAGE_BEING_DISPLAYED())
		{
			GET_HELP_MESSAGE_BOX_SIZE(&fVar13, &fVar14);
			fVar14 += l_U563 + 0.03f;
		}
		else if (IS_IN_SPECTATOR_MODE())
			fVar14 = (0.2155f + l_U563) + l_U986;
		else if (GET_IS_HIDEF())
			fVar14 = (0.06f + l_U563) + l_U986;
		else
			fVar14 = (0.08f + l_U563) + l_U986;
		if (GET_IS_WIDESCREEN())
		{
			fVar15 = 0.3125f;
			fVar16 = 0.4455f;
		}
		else
		{
			fVar15 = 0.3f;
			fVar16 = 0.44f;
		}
		GET_GAME_TIMER(&iVar5);
		GET_FRAME_TIME(&uVar10);
		while (iVar2 != l_U479)
		{
			if (l_U6[iVar2]._fU0 == 1)
			{
				if (GET_IS_HIDEF())
					fVar13 = 0.077f;
				else
					fVar13 = 0.097f;

				iVar3 = sub_89117((l_U6[iVar2]._fU4 - 512) - iVar5, 0, 255);
				SetTextFormat(0, -0.5f, 1.5f, 3, 1, 0, 0, 0, iVar3);
				SET_TEXT_USE_UNDERSCORE(1);
				if (l_U6[iVar2]._fU76._fU64)
					uVar12 = sub_32837(l_U6[iVar2]._fU76._fU0, fVar13, fVar14, fVar15, fVar16, l_U6[iVar2]._fU76._fU68, l_U6[iVar2]._fU76._fU72, l_U6[iVar2]._fU76._fU76, iVar3, 2);
				else
					uVar12 = sub_41553(fVar13, fVar14, fVar15, fVar16, l_U6[iVar2]._fU76._fU68, l_U6[iVar2]._fU76._fU72, l_U6[iVar2]._fU76._fU76, iVar3, 2, l_U6[iVar2]._fU76._fU0);
				fVar13 += uVar12;
				if (l_U6[iVar2]._fU8 == -1)
					fVar13 += sub_58719(0, -0.5f, 1.5f, 3, 1, fVar15, fVar16, " ");
				if (l_U6[iVar2]._fU8 == -2)
				{
					fVar13 += sub_58719(0, -0.5f, 1.5f, 3, 1, fVar15, fVar16, " ");
					SetTextFormat(0, -0.5f, 1.5f, 3, 1, 0, 0, 0, iVar3);
					GET_HUD_COLOUR(1, &uVar6, &uVar7, &uVar8, &uVar9);
					SET_TEXT_USE_UNDERSCORE(1);
					fVar13 += sub_32837(l_U6[iVar2]._fU12, fVar13, fVar14, fVar15, fVar16, uVar6, uVar7, uVar8, iVar3, 2);
					SET_TEXT_USE_UNDERSCORE(1);
					fVar13 += sub_58719(0, -0.5f, 1.5f, 3, 1, fVar15, fVar16, " ");
				}
				else if ((l_U6[iVar2]._fU8 > -1) && (l_U6[iVar2]._fU8 < 36))
				{
					fVar13 += 0.032f / 2;
					DRAW_SPRITE(networkTextures[l_U6[iVar2]._fU8], fVar13, fVar14 + 0.009f, 0.032f, 0.032f, 0.0f, 255, 255, 255, iVar3);
					fVar13 += 0.032f / 2;
				}
				SetTextFormat(0, -0.5f, 1.5f, 3, 1, 0, 0, 0, iVar3);
				SET_TEXT_USE_UNDERSCORE(1);
				if (l_U6[iVar2]._fU156._fU64)
					sub_32837(l_U6[iVar2]._fU156._fU0, fVar13, fVar14, fVar15, fVar16, l_U6[iVar2]._fU156._fU68, l_U6[iVar2]._fU156._fU72, l_U6[iVar2]._fU156._fU76, iVar3, 2);
				else
					sub_41553(fVar13, fVar14, fVar15, fVar16, l_U6[iVar2]._fU156._fU68, l_U6[iVar2]._fU156._fU72, l_U6[iVar2]._fU156._fU76, iVar3, 2, l_U6[iVar2]._fU156._fU0);
				SET_TEXT_USE_UNDERSCORE(0);
				if (iVar3 < 255)
					iVar4++;
				if (l_U6[iVar2]._fU4 <= iVar5)
				{
					l_U563 -= -0.026f;
					ClearFrontMSG(&l_U6[iVar2]);
					incByOne(&l_U480, 8);
					iVar4--;
				}
				fVar14 -= -0.026f;
				incByOne(&iVar2, 8);
			}
			if (l_U6[iVar2]._fU0 == 0)
			{
				if (iVar2 == l_U480 && iVar4 == 0)
					l_U563 = 0.0f;
				iVar2 = l_U479;
			}
		}
		l_U563 -= uVar10 * 0.08f;
		l_U986 = 0.0f;
		fVar11 = -0.026f * (TO_FLOAT(iVar4));
		if (l_U563 <= fVar11)
			l_U563 = fVar11;
		SET_WIDESCREEN_FORMAT(0);
	}
}

void main()
{
	int blips[16];

	if (HAS_SCRIPT_LOADED("network_main"))
		TERMINATE_ALL_SCRIPTS_WITH_THIS_NAME("network_main");
	//FORCE_LOADING_SCREEN(0);
	//DO_SCREEN_FADE_IN(0);
	SET_PLAYER_CONTROL(GET_PLAYER_ID(), true);
	SET_CHAR_VISIBLE(GetOurChar(), true);
	//SET_CHAR_COORDINATES(GetOurChar(), 2175.352f, 761.2235f, 30.0f);
	/*if (DOES_SCRIPT_EXIST("modscript"))
	{
		REQUEST_SCRIPT("modscript");
		while (!HAS_SCRIPT_LOADED("modscript"))
			WAIT(0);
		START_NEW_SCRIPT("modscript", 1024);
		MARK_SCRIPT_AS_NO_LONGER_NEEDED("modscript");
	}*/
	for (int i = 0; i < 16; i++)
		notifyStatus[i] = 0;
	USE_PLAYER_COLOUR_INSTEAD_OF_TEAM_COLOUR(true);
	LoadNetworkTextures();
	GIVE_WEAPON_TO_CHAR(GetOurChar(), WEAPON_PISTOL, AMMO_MAX, false);
	DISPLAY_PLAYER_NAMES(true);
	SET_VOICE_ID_FROM_HEAD_COMPONENT(GetOurChar(), 0, IS_CHAR_MALE(GetOurChar()));
	while (true)
	{
		DoPrintNotifys(blips);
		DoPlayerTaunts();
		if (ShouldDisplayDropDown())
			ShowDropDownDisplay(l_U564[2]._fU24);
		DrawTickerMessages();
		WAIT(0);
	}
}

struct Actormount
{
	char _0x00;
	char _0x01;
	char _padding1;
	char _padding2;
	float _0x04;
	float _0x08;
};

Actormount mountData;

int FixActorMount(int actor)
{
	if (*(int*)(actor + 0x0C) == 0 || !MmIsAddressValid((PVOID)*(int*)(actor + 0x0C)))
	{
		print("Fixing Actor Mount with proper value!");
		return (int)&mountData;
	}
	return *(int*)(actor + 0x0C) + 0x678;
}

void __declspec(naked) FixActorMountCrash()
{
	__asm
	{
		cmplw cr6, r3, r5
		bnelr cr6
		mr r3, r10
		bl FixActorMount
		lis r0, 0x82CE
		ori r0, r0, 0x6350
		mtctr r0
		bctr
	}
}

int FixCutsceneActor(int r3)
{
	if (r3 == 0 || !MmIsAddressValid((PVOID)r3))
	{
		print("Someone tried to cutscene actor crash you!");
		return 0;
	}
	return *(byte*)(r3 + 0xE8);
}

void __declspec(naked) CutsceneActorCrash()
{
	__asm
	{
		lwzx r28, r10, r11
		lwz r3, 0x60(r28)
		bl FixCutsceneActor
		mr r11, r3
		lwz r3, 0x60(r28)
		li r28, 1
		rlwinm r10, r11, 0, 28, 28
		lis r0, 0x82DF
		ori r0, r0, 0xDEA8
		mtctr r0
		bctr
	}
}

void NativeExceptionCheck(Native_s* cxt, DWORD native)
{
	jmp_buf nativeCxtJump;
	int ret = setjmp(nativeCxtJump);
	if (!ret)
	{
		try
		{
			((void(*)(Native_s*))native)(cxt);
		}
		catch (...)
		{
			printToLog("HDD:\\RDRMenu.log", "Native", "XSC Native Handler caught exception calling 0x%X!", native);
			longjmp(nativeCxtJump, 1337);
		}
	}
}

void __declspec(naked) XSCNativeHandlerHook()
{
	__asm
	{
		add r10, r11, r21
		stw r10, 0x98(r1)
		mr r4, r9
		bl NativeExceptionCheck
		lis r0, 0x82AF
		ori r0, r0, 0x4A24
		mtctr r0
		bctr
	}
}

char* titleText = "<0x24DB21>Panah</0x>";
Detour<char*> UiGetStringDetour;
char* UiGetStringHook(char* ui, char* entry)
{
	if (strstr(entry, "title_weap_25"))
		return titleText;
	if (!entry)
		entry = "Common_Null";
	return UiGetStringDetour.CallOriginal(ui, entry);
}

int vehDump = 0;
Detour<void> NetCreator_HandleCreationDetour;
void NetCreator_HandleCreationHook(char* creation, char* r4, QWORD creator)
{
	snuGamer* player = GetPlayerByHostToken(creator);
	if (player && creation)
	{
		NetCreatorType_e type = *(NetCreatorType_e*)(creation + 0x14);
		switch (type)
		{
		case NetGOHActor_e:
		{
			NetCreatorGOHActor* actor = (NetCreatorGOHActor*)creation;
			char actorName[64];
			sprintf(actorName, "rem_%s", player->data.gamertag);
			printf("[%s] - %s created NetGOHActor [Name:%s] [Enum:%s|%i]\n", __FUNCTION__, player->data.gamertag, actor->actorName[0] ? actor->actorName : actorName, _GET_ENUM_STRING_FROM_ENUM(actor->actorEnum), actor->actorEnum);
			if (actor->layout == 0xBBE078AB && actor->actorEnum >= ACTOR_VEHICLE_TRAIN_ArmoredCar01)
			{
				printf("[%s] - %s tried to spawn vehicle in Ambient Layout [%s]\n", __FUNCTION__, player->data.gamertag, _GET_ENUM_STRING_FROM_ENUM(actor->actorEnum));
				actor->layout = jenkinsHash("crashDumpLay");
			}
			if (actor->actorEnum == ACTOR_PLAYER_cs)
				return;
			break;
		}
		case NetGOHProp_e:
		{
			NetCreatorGOHProp* prop = (NetCreatorGOHProp*)creation;
			printf("[%s] - %s created NetGOHProp [Name:%s]\n", __FUNCTION__, player->data.gamertag, prop->propName[0] ? prop->propName : "NO_NAME");
			break;
		}
		case NetGOHPickup_e:
		{
			NetCreatorGOHPickup* pickup = (NetCreatorGOHPickup*)creation;
			printf("[%s] - %s created NetGOHPickup [CRC:0x%X]\n", __FUNCTION__, player->data.gamertag, pickup->itemCRC);
			break;
		}
		case RdR2NetClient_e:
		{
			NetCreatorClient* client = (NetCreatorClient*)creation;
			printf("[%s] - %s created RdR2NetClient\n", __FUNCTION__, player->data.gamertag);
			break;
		}
		case NetGameWeather_e:
		{
			NetCreatorWeather* weather = (NetCreatorWeather*)creation;
			printf("[%s] - %s created NetGameWeather\n", __FUNCTION__, player->data.gamertag);
			break;
		}
		}
	}
	NetCreator_HandleCreationDetour.CallOriginal(creation, r4, creator);
}

/*EXPLOSION_ExplosionLargeNoFx "ExplosionLargeNoFx"
EXPLOSION_CannonballExplosion "CannonballExplosion"
EXPLOSION_FireBottleExplosion "FireBottleExplosion"*/

Detour<void> NetProjectile_RemoteExplosion_HandleDetour;
void NetProjectile_RemoteExplosion_HandleHook(char* exp, char* r4, QWORD creator)
{
	static int playerCreateTimers[16];
	static int playerCreateCount[16];

	snuGamer* player = GetPlayerByHostToken(creator);
	if (player && exp)
	{
		int slot = player->getSlot();
		if (!playerCreateTimers[slot])
			playerCreateTimers[slot] = GetTickCount();

		DWORD time = GetTickCount() - playerCreateTimers[slot];
		if (time > 60000)
		{
			playerCreateTimers[slot] = 0;
			playerCreateCount[slot] = 0;
		}
		else if (playerCreateCount[slot] >= 7)
			return;
		playerCreateCount[slot]++;
		printf("[%s] - %s created 0x%X explosion\n", __FUNCTION__, player->data.gamertag, *(DWORD*)(exp + 0x34));
	}
	NetProjectile_RemoteExplosion_HandleDetour.CallOriginal(exp, r4, creator);
}

Detour<void> NetProjectile_RemoteExplodeTarget_HandleDetour;
void NetProjectile_RemoteExplodeTarget_HandleHook(char* exp, char* r4, QWORD creator)
{
	QWORD hostToken = creator;
	snuGamer* player = GetPlayerByHostToken(creator);
	if (player && exp)
	{
		char* netActor = GetNetGOHFromNetworkID(*(DWORD*)(exp + 4));
		if (netActor)
		{
			printf("[%s] - %s tried to remote explode actor 0x%X\n", __FUNCTION__, player->data.gamertag, netActor);
			if (GET_PLAYER_ACTOR(0) == *(int*)(netActor + 0x180))
			{
				printf("[%s] - %s tried to remote explode us blocking...\n", __FUNCTION__, player->data.gamertag);
				return;
			}
		}
	}
	NetProjectile_RemoteExplodeTarget_HandleDetour.CallOriginal(exp, r4, creator);
}

ScriptThread* mainThread;
Detour<void> RemoveWeaponFromActorDetour;
void RemoveWeaponFromActorHook(char* actor, int weapon)
{
	if (weapon != 31 || *(ScriptThread**)0x831AB888 == mainThread) //Don't remove ER unless its called from our thread
		RemoveWeaponFromActorDetour.CallOriginal(actor, weapon);
}

bool initalized = false;
int mainScriptSlot;
pgPtrCollection<ScriptThread>* scrThreadCollection = (pgPtrCollection<ScriptThread>*)0x831AB898;
Detour<void> WAITDetour;
void WAITHook(void* r3)
{
	if (!initalized)
	{
		mainScriptSlot = scrThreadCollection->count() - 1;
		mainThread->m_context.threadID = mainScriptSlot;
		scrThreadCollection->set(mainScriptSlot, mainThread);
		initalized = true;
	}
	if (initalized && mainThread)
		mainThread->Reset(mainScriptSlot, nullptr, NULL);
	WAITDetour.CallOriginal(r3);
}

BOOL haveWeBootedGame;
extern Caller* call;
BOOL Init()
{
	if (!mainThread)
	{
		mainThread = new ScriptThread();
		if (!mainThread) //failed to allocate our scriptThread
		{
			printToLog("HDD:\\RDRMenu.log", "System", "Failed to allocate ScriptThread!");
			return FALSE;
		}
	}
	if (!call)
	{
		call = new Caller();
		if (!call)
		{
			printToLog("HDD:\\RDRMenu.log", "System", "Failed to allocate Native Caller!");
			return FALSE; //failed to allocate native caller
		}
	}

	NetCreator_HandleCreationDetour.SetupDetour(0x826B8D30, NetCreator_HandleCreationHook);
	NetProjectile_RemoteExplosion_HandleDetour.SetupDetour(0x82676B30, NetProjectile_RemoteExplosion_HandleHook);
	NetProjectile_RemoteExplodeTarget_HandleDetour.SetupDetour(0x82676D30, NetProjectile_RemoteExplodeTarget_HandleHook);

	ZeroMemory(&mountData, sizeof(mountData));
	mountData._0x04 = 0.0f;
	mountData._0x08 = 0.0f;
	PatchInJump((DWORD*)0x8233415C, FixActorMountCrash, FALSE);
	PatchInJump((DWORD*)0x82C8B1F4, FixActorMountCrash, FALSE);
	PatchInJump((DWORD*)0x82DFDE98, CutsceneActorCrash, FALSE);
	PatchInJump((DWORD*)0x82AF4A14, XSCNativeHandlerHook, FALSE);
	UiGetStringDetour.SetupDetour(0x829C7698, UiGetStringHook);
	
	//Util Detours
	if (!WAITDetour.SetupDetour(0x822ADBA0, WAITHook))
	{
		printToLog("HDD:\\RDRMenu.log", "System", "Failed to setup Wait Hook!");
		return FALSE;
	}

	*(DWORD*)0x824212D4 = 0x60000000; //File Bypass
	
	initalized = false;
	XNotify(L"Red Dead Redemption Menu Loaded!");
	printToLog("HDD:\\RDRMenu.log", "System", "Game Setup Ran!");
	haveWeBootedGame = TRUE;
	return TRUE;
}