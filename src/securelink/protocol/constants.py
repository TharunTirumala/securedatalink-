"""Protocol constants for the SecureLink wire format."""

# Protocol versions
PROTOCOL_VERSION: int = 1
PROTOCOL_VERSION_V1: int = 1
PROTOCOL_VERSION_V2: int = 2
PROTOCOL_VERSION_V3: int = 3   # V3: 2-byte epoch field; avoids 255-epoch overflow

DEFAULT_KEY_EPOCH: int = 1

# V1: 1B ver + 2B sender_id + 1B epoch + 8B seq + 8B timestamp
HEADER_FORMAT_V1: str = ">BHBQ d"
HEADER_FORMAT: str = HEADER_FORMAT_V1

# V2: 1B ver + 2B sender_id + 1B epoch + 4B session_id + 8B seq + 8B timestamp
HEADER_FORMAT_V2: str = ">BHBIQd"  # 1B ver + 2B sid + 1B epoch + 4B session_id + 8B seq + 8B ts

# V3: 1B ver + 2B sender_id + 2B epoch + 4B session_id + 8B seq + 8B timestamp
HEADER_FORMAT_V3: str = ">BHHIQd"  # 1B ver + 2B sid + 2B epoch + 4B session_id + 8B seq + 8B ts

HEADER_SIZE_V1: int = 20
HEADER_SIZE_V2: int = 24
HEADER_SIZE_V3: int = 25
HEADER_SIZE: int = HEADER_SIZE_V1

# Epoch limits
MAX_EPOCH_V1V2: int = 255   # B (unsigned byte) max
MAX_EPOCH_V3: int = 65535   # H (unsigned short) max

SALT_SIZE: int = 4
NONCE_SIZE: int = 12  # 4 bytes salt + 8 bytes seq
TAG_SIZE: int = 16
SIGNATURE_SIZE: int = 64  # IEEE P1363 raw r (32B) + s (32B)

MIN_FRAME_SIZE: int = HEADER_SIZE + TAG_SIZE + SIGNATURE_SIZE       # 100 bytes
MIN_FRAME_SIZE_V2: int = HEADER_SIZE_V2 + TAG_SIZE + SIGNATURE_SIZE  # 104 bytes
MIN_FRAME_SIZE_V3: int = HEADER_SIZE_V3 + TAG_SIZE + SIGNATURE_SIZE  # 105 bytes
