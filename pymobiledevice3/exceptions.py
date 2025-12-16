__all__ = [
    "AccessDeniedError",
    "AfcException",
    "AfcFileNotFoundError",
    "AlreadyMountedError",
    "AmfiError",
    "ArbitrationError",
    "ArgumentError",
    "BadCommandError",
    "BadDevError",
    "CannotStopSessionError",
    "CloudConfigurationAlreadyPresentError",
    "ConnectionFailedError",
    "ConnectionFailedToUsbmuxdError",
    "ConnectionTerminatedError",
    "CoreDeviceError",
    "DeprecationError",
    "DeveloperModeError",
    "DeveloperModeIsNotEnabledError",
    "DeviceAlreadyInUseError",
    "DeviceHasPasscodeSetError",
    "DeviceNotFoundError",
    "DeviceVersionNotSupportedError",
    "DisableMemoryLimitError",
    "DvtDirListError",
    "DvtException",
    "ExtractingStackshotError",
    "FatalPairingError",
    "FeatureNotSupportedError",
    "GetProhibitedError",
    "IRecvError",
    "IRecvNoDeviceConnectedError",
    "IncorrectModeError",
    "InspectorEvaluateError",
    "InternalError",
    "InvalidConnectionError",
    "InvalidHostIDError",
    "InvalidServiceError",
    "LaunchingApplicationError",
    "LockdownError",
    "MessageNotSupportedError",
    "MissingValueError",
    "MuxException",
    "MuxVersionError",
    "NoDeviceConnectedError",
    "NotEnoughDiskSpaceError",
    "NotMountedError",
    "NotPairedError",
    "NotTrustedError",
    "NotificationTimeoutError",
    "OSNotSupportedError",
    "PairingDialogResponsePendingError",
    "PairingError",
    "PasscodeRequiredError",
    "PasswordRequiredError",
    "ProfileError",
    "PyMobileDevice3Exception",
    "QuicProtocolNotSupportedError",
    "RSDRequiredError",
    "RemoteAutomationNotEnabledError",
    "RemotePairingCompletedError",
    "SetProhibitedError",
    "StartServiceError",
    "SysdiagnoseTimeoutError",
    "TSSError",
    "TunneldConnectionError",
    "UnrecognizedSelectorError",
    "UnsupportedCommandError",
    "UserDeniedPairingError",
    "WebInspectorNotEnabledError",
    "WirError",
]

from typing import Optional


class PyMobileDevice3Exception(Exception):
    pass


class DeviceVersionNotSupportedError(PyMobileDevice3Exception):
    pass


class IncorrectModeError(PyMobileDevice3Exception):
    pass


class NotTrustedError(PyMobileDevice3Exception):
    pass


class PairingError(PyMobileDevice3Exception):
    pass


class NotPairedError(PyMobileDevice3Exception):
    pass


class CannotStopSessionError(PyMobileDevice3Exception):
    pass


class PasswordRequiredError(PairingError):
    pass


class StartServiceError(PyMobileDevice3Exception):
    def __init__(self, service_name: str, message: str) -> None:
        super().__init__()
        self.service_name = service_name
        self.message = message


class FatalPairingError(PyMobileDevice3Exception):
    pass


class NoDeviceConnectedError(PyMobileDevice3Exception):
    pass


class InterfaceIndexNotFoundError(PyMobileDevice3Exception):
    def __init__(self, address: str) -> None:
        super().__init__()
        self.address = address


class DeviceNotFoundError(PyMobileDevice3Exception):
    def __init__(self, udid: str) -> None:
        super().__init__()
        self.udid = udid


class TunneldConnectionError(PyMobileDevice3Exception):
    pass


class MuxException(PyMobileDevice3Exception):
    pass


class MuxVersionError(MuxException):
    pass


class BadCommandError(MuxException):
    pass


class BadDevError(MuxException):
    pass


class ConnectionFailedError(MuxException):
    pass


class ConnectionFailedToUsbmuxdError(ConnectionFailedError):
    pass


class ArgumentError(PyMobileDevice3Exception):
    pass


class AfcException(PyMobileDevice3Exception, OSError):
    def __init__(self, message: str, status: str, filename: Optional[str] = None) -> None:
        OSError.__init__(self, status, message)
        self.status = status
        self.filename = filename


class AfcFileNotFoundError(AfcException):
    pass


class DvtException(PyMobileDevice3Exception):
    """Domain exception for DVT operations."""


class UnrecognizedSelectorError(DvtException):
    """Attempted to call an unrecognized selector from DVT."""


class DvtDirListError(DvtException):
    """Raise when directory listing fails."""


class NotMountedError(PyMobileDevice3Exception):
    """Given image for umount wasn't mounted in the first place"""


class AlreadyMountedError(PyMobileDevice3Exception):
    """Given image for mount has already been mounted in the first place"""


class MissingManifestError(PyMobileDevice3Exception):
    """No manifest could be found"""


class UnsupportedCommandError(PyMobileDevice3Exception):
    """Given command isn't supported for this iOS version"""


class ExtractingStackshotError(PyMobileDevice3Exception):
    """Raise when stackshot is not received in the core profile session."""


class ConnectionTerminatedError(PyMobileDevice3Exception):
    """Raise when a connection is terminated abruptly."""


class StreamClosedError(ConnectionTerminatedError):
    """Raise when trying to send a message on a closed stream."""


class WebInspectorNotEnabledError(PyMobileDevice3Exception):
    """Raise when Web Inspector is not enabled."""


class RemoteAutomationNotEnabledError(PyMobileDevice3Exception):
    """Raise when Web Inspector remote automation is not enabled."""


class WirError(PyMobileDevice3Exception):
    """Raise when Webinspector WIR command fails."""


class InternalError(PyMobileDevice3Exception):
    """Some internal Apple error"""


class ArbitrationError(PyMobileDevice3Exception):
    """Arbitration failed"""


class DeviceAlreadyInUseError(ArbitrationError):
    """Device is already checked-in by someone"""

    def __init__(self, response: dict) -> None:
        super().__init__()
        self.message: Optional[str] = response.get("message")
        self.owner: Optional[str] = response.get("owner")
        self.result: Optional[str] = response.get("result")


class DeveloperModeIsNotEnabledError(PyMobileDevice3Exception):
    """Raise when mounting failed because developer mode is not enabled."""


class DeveloperDiskImageNotFoundError(PyMobileDevice3Exception):
    """Failed to locate the correct DeveloperDiskImage.dmg"""


class DeveloperModeError(PyMobileDevice3Exception):
    """Raise when amfid failed to enable developer mode."""


class LockdownError(PyMobileDevice3Exception):
    """lockdown general error"""

    def __init__(self, message: str, identifier: Optional[str] = None) -> None:
        super().__init__(message)
        self.identifier: Optional[str] = identifier


class GetProhibitedError(LockdownError):
    pass


class SetProhibitedError(LockdownError):
    pass


class PairingDialogResponsePendingError(PairingError):
    """User hasn't yet confirmed the device is trusted"""


class UserDeniedPairingError(PairingError):
    pass


class InvalidHostIDError(PairingError):
    pass


class MissingValueError(LockdownError):
    """raised when attempting to query non-existent domain/key"""


class InvalidConnectionError(LockdownError):
    pass


class PasscodeRequiredError(LockdownError):
    """passcode must be present for this action"""


class AmfiError(PyMobileDevice3Exception):
    pass


class DeviceHasPasscodeSetError(AmfiError):
    pass


class NotificationTimeoutError(PyMobileDevice3Exception, TimeoutError):
    pass


class ProfileError(PyMobileDevice3Exception):
    pass


class CloudConfigurationAlreadyPresentError(ProfileError):
    pass


class IRecvError(PyMobileDevice3Exception):
    pass


class IRecvNoDeviceConnectedError(IRecvError):
    pass


class MessageNotSupportedError(PyMobileDevice3Exception):
    pass


class InvalidServiceError(LockdownError):
    pass


class InspectorEvaluateError(PyMobileDevice3Exception):
    def __init__(
        self,
        class_name: str,
        message: str,
        line: Optional[int] = None,
        column: Optional[int] = None,
        stack: Optional[list[str]] = None,
    ) -> None:
        super().__init__()
        self.class_name = class_name
        self.message = message
        self.line = line
        self.column = column
        self.stack = stack

    def __str__(self) -> str:
        stack_trace = (
            "\n".join([f"\t - {frame}" for frame in self.stack]) if self.stack is not None else "<no stack trace>"
        )
        return f"{self.class_name}: {self.message}.\nLine: {self.line} Column: {self.column}\nStack: {stack_trace}"


class LaunchingApplicationError(PyMobileDevice3Exception):
    pass


class AppInstallError(PyMobileDevice3Exception):
    pass


class AppNotInstalledError(PyMobileDevice3Exception):
    pass


class CoreDeviceError(PyMobileDevice3Exception):
    pass


class AccessDeniedError(PyMobileDevice3Exception):
    """Need extra permissions to execute this command"""


class NoSuchBuildIdentityError(PyMobileDevice3Exception):
    pass


class MobileActivationException(PyMobileDevice3Exception):
    """Mobile activation can not be done"""


class NotEnoughDiskSpaceError(PyMobileDevice3Exception):
    """Computer does not have enough disk space for the intended operation"""


class DeprecationError(PyMobileDevice3Exception):
    """The requested action/service/method is deprecated"""


class RSDRequiredError(PyMobileDevice3Exception):
    """The requested action requires an RSD object"""

    def __init__(self, identifier: str) -> None:
        self.identifier = identifier
        super().__init__()


class SysdiagnoseTimeoutError(PyMobileDevice3Exception, TimeoutError):
    """Timeout collecting new sysdiagnose archive"""


class SupportError(PyMobileDevice3Exception):
    def __init__(self, os_name: str) -> None:
        super().__init__()
        self.os_name: str = os_name


class OSNotSupportedError(SupportError):
    """Operating system is not supported."""


class FeatureNotSupportedError(SupportError):
    """Feature has not been implemented for OS."""

    def __init__(self, os_name: str, feature: str) -> None:
        super().__init__(os_name)
        self.feature: str = feature


class QuicProtocolNotSupportedError(PyMobileDevice3Exception):
    """QUIC tunnel support was removed on iOS 18.2+"""


class RemotePairingCompletedError(PyMobileDevice3Exception):
    """
    Raised upon pairing completion using the `remotepairingdeviced` service (RemoteXPC).

    remotepairingdeviced closes connection after pairing, so client must re-establish it after pairing is
    completed.
    """


class DisableMemoryLimitError(PyMobileDevice3Exception):
    """Disabling memory limit fails."""


class ProtocolError(PyMobileDevice3Exception):
    """An unexpected protocol message was received"""


class TSSError(PyMobileDevice3Exception):
    """An unexpected message was received from apple ticket server"""


class ServiceNotConnectedError(PyMobileDevice3Exception):
    """Attempted to use a service before calling connect()"""
