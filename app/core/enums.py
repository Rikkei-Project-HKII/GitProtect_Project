from enum import Enum

class ConnectionStatusEnum(str, Enum):
    ACTIVE = "active"
    ERROR = "error"

class ScanStatusEnum(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class AlertSourceEnum(str, Enum):
    GITPROTECT_SCANNER = "gitprotect_scanner"
    GITHUB_NATIVE = "github_native"

class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class AlertStatusEnum(str, Enum):
    OPEN = "open"
    IN_REVIEW = "in_review"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    IGNORED = "ignored"

class ActorTypeEnum(str, Enum):
    SYSTEM = "system"
    INTERNAL_OPERATOR = "internal_operator"

class CharsetTypeEnum(str, Enum):
    HEX = "hex"
    BASE32 = "base32"
    BASE64 = "base64"
    ASCII = "ascii"
    DYNAMIC = "dynamic"
    NONE = "none"
