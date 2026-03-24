#![allow(non_camel_case_types)]
#![allow(non_upper_case_globals)]

use std::ptr::null;

#[cfg(windows)]
mod platform {
    use std::ffi::c_void;

    pub type FilePathCharType = *const u16;
    pub type PlatformFile = *mut c_void;

    pub const kInvalidPlatformFile: PlatformFile = 0xFFFFFFFF as _;
}

#[cfg(not(windows))]
mod platform {
    pub type FilePathCharType = *const u8;
    pub type PlatformFile = i32;

    pub const kInvalidPlatformFile: PlatformFile = -1;
}

#[repr(C)]
pub struct HostFile {
    file_path: platform::FilePathCharType,
    file: platform::PlatformFile,
    sig_file: platform::PlatformFile,
}

impl Default for HostFile {
    fn default() -> Self {
        Self {
            file_path: null(),
            file: platform::kInvalidPlatformFile,
            sig_file: platform::kInvalidPlatformFile,
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    kSuccess,

    /// Decoder needs more data to produce a decoded frame/sample.
    kNeedMoreData,

    /// The required decryption key is not available.
    kNoKey,

    /// Initialization error.
    kInitializationError,

    /// Decryption failed.
    kDecryptError,

    /// Error decoding audio or video.
    kDecodeError,

    /// Decoder is not ready for initialization.
    kDeferredInitialization,
}

/// Exceptions used by the CDM to reject promises.
/// https://w3c.github.io/encrypted-media/#exceptions
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exception {
    kExceptionTypeError,
    kExceptionNotSupportedError,
    kExceptionInvalidStateError,
    kExceptionQuotaExceededError,
}

/// The encryption scheme. The definitions are from ISO/IEC 23001-7:2016.
#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum EncryptionScheme {
    #[default]
    kUnencrypted,
    /// 'cenc' subsample encryption using AES-CTR mode.
    kCenc,
    /// 'cbcs' pattern encryption using AES-CBC mode.
    kCbcs,
}

/// The pattern used for pattern encryption. Note that ISO/IEC 23001-7:2016
/// defines each block to be 16-bytes.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Pattern {
    /// Count of the encrypted blocks.
    pub crypt_byte_block: u32,

    /// Count of the unencrypted blocks.
    pub skip_byte_block: u32,
}

#[repr(u8)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum ColorRange {
    #[default]
    kInvalid,
    /// 709 color range with RGB values ranging from 16 to 235.
    kLimited,
    /// Full RGB color range with RGB values from 0 to 255.
    kFull,
    /// Range is defined by [`ColorSpace::transfer_id`] and [`ColorSpace::matrix_id`].
    kDerived,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ColorSpace {
    /// 7.1 colour primaries, table 2
    pub primary_id: u8,
    /// 7.2 transfer characteristics, table 3
    pub transfer_id: u8,
    /// 7.3 matrix coefficients, table 4
    pub matrix_id: u8,
    pub range: ColorRange,
}

/// An input buffer can be split into several continuous subsamples.
/// A SubsampleEntry specifies the number of clear and cipher bytes in each
/// subsample. For example, the following buffer has three subsamples:
///
/// |<----- subsample1 ----->|<----- subsample2 ----->|<----- subsample3 ----->|
/// |   clear1   |  cipher1  |  clear2  |   cipher2   | clear3 |    cipher3    |
///
/// For decryption, all of the cipher bytes in a buffer should be concatenated
/// (in the subsample order) into a single logical stream. The clear bytes should
/// not be considered as part of decryption.
///
/// Stream to decrypt:   |  cipher1  |   cipher2   |    cipher3    |
/// Decrypted stream:    | decrypted1|  decrypted2 |   decrypted3  |
///
/// After decryption, the decrypted bytes should be copied over the position
/// of the corresponding cipher bytes in the original buffer to form the output
/// buffer. Following the above example, the decrypted buffer should be:
///
/// |<----- subsample1 ----->|<----- subsample2 ----->|<----- subsample3 ----->|
/// |   clear1   | decrypted1|  clear2  |  decrypted2 | clear3 |   decrypted3  |
///
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct SubsampleEntry {
    pub clear_bytes: u32,
    pub cipher_bytes: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct InputBuffer_2 {
    /// Pointer to the beginning of the input data.
    pub data: *const u8,
    /// Size (in bytes) of [`InputBuffer_2::data`].
    pub data_size: u32,

    pub encryption_scheme: EncryptionScheme,

    /// Key ID to identify the decryption key.
    pub key_id: *const u8,
    /// Size (in bytes) of [`InputBuffer_2::key_id`].
    pub key_id_size: u32,

    /// Initialization vector.
    pub iv: *const u8,
    /// Size (in bytes) of [`InputBuffer_2::iv`].
    pub iv_size: u32,

    pub subsamples: *const SubsampleEntry,
    /// Number of subsamples in [`InputBuffer_2::subsamples`].
    pub num_subsamples: u32,

    /// [`InputBuffer_2::pattern`] is required if [`InputBuffer_2::encryption_scheme`] specifies pattern encryption.
    pub pattern: Pattern,

    /// Presentation timestamp in microseconds
    pub timestamp: u64,
}

#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AudioCodec {
    #[default]
    kUnknownAudioCodec,
    kCodecVorbis,
    kCodecAac,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct AudioDecoderConfig_2 {
    pub codec: AudioCodec,
    pub channel_count: i32,
    pub bits_per_channel: i32,
    pub samples_per_second: i32,

    /// Optional byte data required to initialize audio decoders, such as the
    /// vorbis setup header.
    pub extra_data: *mut u8,
    pub extra_data_size: u32,

    /// Encryption scheme.
    pub encryption_scheme: EncryptionScheme,
}

#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum AudioFormat {
    /// Unknown format value. Used for error reporting.
    #[default]
    kUnknownAudioFormat = 0,
    /// Interleaved unsigned 8-bit w/ bias of 128.
    kAudioFormatU8,
    /// Interleaved signed 16-bit.
    kAudioFormatS16,
    /// Interleaved signed 32-bit.
    kAudioFormatS32,
    /// Interleaved float 32-bit.
    kAudioFormatF32,
    /// Signed 16-bit planar.
    kAudioFormatPlanarS16,
    /// Float 32-bit planar.
    kAudioFormatPlanarF32,
}

/// Surface formats based on FOURCC labels, see: http://www.fourcc.org/yuv.php
/// Values are chosen to be consistent with Chromium's VideoPixelFormat values.
#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum VideoFormat {
    /// Unknown format value. Used for error reporting.
    #[default]
    kUnknownVideoFormat = 0,
    /// 12bpp YVU planar 1x1 Y, 2x2 VU samples.
    kYv12 = 1,
    /// 12bpp YUV planar 1x1 Y, 2x2 UV samples.
    kI420 = 2,

    // In the following formats, each sample uses 16-bit in storage, while the
    // sample value is stored in the least significant N bits where N is
    // specified by the number after "P". For example, for YUV420P9, each Y, U,
    // and V sample is stored in the least significant 9 bits in a 2-byte block.
    kYUV420P9 = 16,
    kYUV420P10 = 17,
    kYUV422P9 = 18,
    kYUV422P10 = 19,
    kYUV444P9 = 20,
    kYUV444P10 = 21,
    kYUV420P12 = 22,
    kYUV422P12 = 23,
    kYUV444P12 = 24,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Size {
    pub width: i32,
    pub height: i32,
}

#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodec {
    #[default]
    kUnknownVideoCodec = 0,
    kCodecVp8,
    kCodecH264,
    kCodecVp9,
    kCodecAv1,
}

#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum VideoCodecProfile {
    #[default]
    kUnknownVideoCodecProfile = 0,
    kProfileNotNeeded,
    kH264ProfileBaseline,
    kH264ProfileMain,
    kH264ProfileExtended,
    kH264ProfileHigh,
    kH264ProfileHigh10,
    kH264ProfileHigh422,
    kH264ProfileHigh444Predictive,
    kVP9Profile0,
    kVP9Profile1,
    kVP9Profile2,
    kVP9Profile3,
    kAv1ProfileMain,
    kAv1ProfileHigh,
    kAv1ProfilePro,
}

/// Deprecated: New CDM implementations should use VideoDecoderConfig_3.
/// Note that this struct is organized so that sizeof(VideoDecoderConfig_2)
/// equals the sum of sizeof() all members in both 32-bit and 64-bit compiles.
/// Padding has been added to keep the fields aligned.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct VideoDecoderConfig_2 {
    pub codec: VideoCodec,
    pub profile: VideoCodecProfile,
    pub format: VideoFormat,
    /// Padding
    _pad1: u32,

    /// Width and height of video frame immediately post-decode. Not all pixels
    /// in this region are valid.
    pub coded_size: Size,

    /// Optional byte data required to initialize video decoders, such as H.264
    /// AAVC data.
    pub extra_data: *mut u8,
    pub extra_data_size: u32,

    pub encryption_scheme: EncryptionScheme,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct VideoDecoderConfig_3 {
    pub codec: VideoCodec,
    pub profile: VideoCodecProfile,
    pub format: VideoFormat,
    pub color_space: ColorSpace,

    /// Width and height of video frame immediately post-decode. Not all pixels
    /// in this region are valid.
    pub coded_size: Size,

    /// Optional byte data required to initialize video decoders, such as H.264
    /// AAVC data.
    pub extra_data: *mut u8,
    pub extra_data_size: u32,

    pub encryption_scheme: EncryptionScheme,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    kStreamTypeAudio,
    kStreamTypeVideo,
}

/// Structure provided to ContentDecryptionModule::OnPlatformChallengeResponse()
/// after a platform challenge was initiated via Host::SendPlatformChallenge().
/// All values will be NULL / zero in the event of a challenge failure.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct PlatformChallengeResponse {
    /// `challenge` provided during Host::SendPlatformChallenge() combined with
    /// nonce data and signed with the platform's private key.
    pub signed_data: *const u8,
    pub signed_data_length: u32,

    /// RSASSA-PKCS1-v1_5-SHA256 signature of the [`PlatformChallengeResponse::signed_data`] block.
    pub signed_data_signature: *const u8,
    pub signed_data_signature_length: u32,

    /// X.509 device specific certificate for the `service_id` requested.
    pub platform_key_certificate: *const u8,
    pub platform_key_certificate_length: u32,
}

/// The current status of the associated key. The valid types are defined in the
/// spec: https://w3c.github.io/encrypted-media/#dom-mediakeystatus
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    kUsable = 0,
    kInternalError = 1,
    kExpired = 2,
    kOutputRestricted = 3,
    kOutputDownscaled = 4,
    kStatusPending = 5,
    kReleased = 6,
}

/// The current status of the associated key. The valid types are defined in the
/// spec: https://w3c.github.io/encrypted-media/#dom-mediakeystatus
/// Note: For forward compatibility, Host implementations must gracefully handle
/// unexpected (new) enum values, e.g. no-op. This is used by the CDM Interfaces
/// starting from CDM_12.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus_2 {
    kUsable = 0,
    kInternalError = 1,
    kExpired = 2,
    kOutputRestricted = 3,
    kOutputDownscaled = 4,
    kStatusPending = 5,
    kReleased = 6,
    kUsableInFuture = 7,
}

/// Used when passing arrays of key information. Does not own the referenced
/// data. [`KeyInformation::system_code`] is an additional error code for unusable keys and
/// should be 0 when [`KeyInformation::status`] == kUsable.
#[derive(Debug, Clone, Copy)]
pub struct KeyInformation {
    pub key_id: *const u8,
    pub key_id_size: u32,
    pub status: KeyStatus,
    pub system_code: u32,
}

/// Used when passing arrays of key information. Does not own the referenced
/// data. [`KeyInformation_2::system_code`] is an additional error code for unusable keys and
/// should be 0 when [`KeyInformation_2::status`] == kUsable. Used by CDM12 and beyond.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct KeyInformation_2 {
    pub key_id: *const u8,
    pub key_id_size: u32,
    pub status: KeyStatus_2,
    pub system_code: u32,
}

/// Supported output protection methods for use with EnableOutputProtection() and
/// returned by OnQueryOutputProtectionStatus().
#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OutputProtectionMethods {
    #[default]
    kProtectionNone = 0,
    kProtectionHDCP = 1 << 0,
}

/// Connected output link types returned by OnQueryOutputProtectionStatus().
#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OutputLinkTypes {
    #[default]
    kLinkTypeNone = 0,
    kLinkTypeUnknown = 1 << 0,
    kLinkTypeInternal = 1 << 1,
    kLinkTypeVGA = 1 << 2,
    kLinkTypeHDMI = 1 << 3,
    kLinkTypeDVI = 1 << 4,
    kLinkTypeDisplayPort = 1 << 5,
    kLinkTypeNetwork = 1 << 6,
}

/// Result of the QueryOutputProtectionStatus() call.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryResult {
    kQuerySucceeded = 0,
    kQueryFailed,
}

/// The Initialization Data Type. The valid types are defined in the spec:
/// https://w3c.github.io/encrypted-media/format-registry/initdata/index.html#registry
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitDataType {
    kCenc = 0,
    kKeyIds = 1,
    kWebM = 2,
}

/// The type of session to create. The valid types are defined in the spec:
/// https://w3c.github.io/encrypted-media/#dom-mediakeysessiontype
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionType {
    kTemporary = 0,
    kPersistentLicense = 1,
}

/// The type of the message event.  The valid types are defined in the spec:
/// https://w3c.github.io/encrypted-media/#dom-mediakeymessagetype
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    kLicenseRequest = 0,
    kLicenseRenewal = 1,
    kLicenseRelease = 2,
    kIndividualizationRequest = 3,
}

#[repr(u32)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum HdcpVersion {
    #[default]
    kHdcpVersionNone,
    kHdcpVersion1_0,
    kHdcpVersion1_1,
    kHdcpVersion1_2,
    kHdcpVersion1_3,
    kHdcpVersion1_4,
    kHdcpVersion2_0,
    kHdcpVersion2_1,
    kHdcpVersion2_2,
    kHdcpVersion2_3,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Policy {
    pub min_hdcp_version: HdcpVersion,
}
