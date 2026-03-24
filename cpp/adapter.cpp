#include "adapter.h"
#include "cdm/content_decryption_module.h"
#include "wrapper.h"
#include <cassert>
#include <new>

WidevineAdapter::WidevineAdapter(void *context) : cdm::Host_11() {
  context_ = context;
};
WidevineAdapter::~WidevineAdapter() = default;

void WidevineAdapter::OnInitialized(bool success) {
  rs_on_initialized(context_, success);
}

cdm::Buffer *WidevineAdapter::Allocate(uint32_t capacity) {
  return new (std::nothrow) WidevineBuffer(capacity);
};

void WidevineAdapter::SetTimer(int64_t delay_ms, void *context) {}

cdm::Time WidevineAdapter::GetCurrentWallTime() { return 0; }

void WidevineAdapter::OnResolveNewSessionPromise(uint32_t promise_id,
                                                 const char *session_id,
                                                 uint32_t session_id_size) {
  rs_on_resolve_session_promise(context_, promise_id, session_id,
                                session_id_size);
};

void WidevineAdapter::OnResolveKeyStatusPromise(uint32_t promise_id,
                                                cdm::KeyStatus key_status) {};

void WidevineAdapter::OnResolvePromise(uint32_t promise_id) {
  rs_on_resolve_promise(context_, promise_id);
};

void WidevineAdapter::OnRejectPromise(uint32_t promise_id,
                                      cdm::Exception exception,
                                      uint32_t system_code,
                                      const char *error_message,
                                      uint32_t error_message_size) {
  rs_on_reject_promise(context_, promise_id, exception, system_code,
                       error_message, error_message_size);
};

void WidevineAdapter::OnSessionMessage(const char *session_id,
                                       uint32_t session_id_size,
                                       cdm::MessageType message_type,
                                       const char *message,
                                       uint32_t message_size) {
  rs_on_session_message(context_, session_id, session_id_size, message_type,
                        message, message_size);
}

void WidevineAdapter::OnSessionKeysChange(const char *session_id,
                                          uint32_t session_id_size,
                                          bool has_additional_usable_key,
                                          const cdm::KeyInformation *keys_info,
                                          uint32_t keys_info_count) {
  rs_on_session_keys_change(context_, session_id, session_id_size,
                            has_additional_usable_key, keys_info,
                            keys_info_count);
}

void WidevineAdapter::OnSessionClosed(const char *session_id,
                                      uint32_t session_id_size) {};
void WidevineAdapter::SendPlatformChallenge(const char *service_id,
                                            uint32_t service_id_size,
                                            const char *challenge,
                                            uint32_t challenge_size) {};
void WidevineAdapter::EnableOutputProtection(uint32_t desired_protection_mask) {
};
void WidevineAdapter::QueryOutputProtectionStatus() {};
void WidevineAdapter::OnDeferredInitializationDone(cdm::StreamType stream_type,
                                                   cdm::Status decoder_status) {
};
void WidevineAdapter::OnExpirationChange(const char *session_id,
                                         uint32_t session_id_size,
                                         cdm::Time new_expiry_time) {};
void WidevineAdapter::ReportMetrics(cdm::MetricName metric_name,
                                    uint64_t value) {};
void WidevineAdapter::RequestStorageId(uint32_t version) {};
cdm::FileIO *WidevineAdapter::CreateFileIO(cdm::FileIOClient *client) {
  return nullptr;
};

WidevineBuffer::~WidevineBuffer() = default;
WidevineBuffer::WidevineBuffer(uint32_t aSize) {
  buffer_ = new uint8_t[aSize];
  bufferCapacity_ = aSize;
}

void WidevineBuffer::Destroy() {
  delete[] buffer_;
  buffer_ = nullptr;
  bufferCapacity_ = 0;
  bufferSize_ = 0;
}

uint32_t WidevineBuffer::Capacity() const { return bufferCapacity_; }
uint8_t *WidevineBuffer::Data() { return buffer_; }
void WidevineBuffer::SetSize(uint32_t aSize) { bufferSize_ = aSize; }
uint32_t WidevineBuffer::Size() const { return bufferSize_; }

WidevineDecryptedBlock::WidevineDecryptedBlock()
    : mBuffer(nullptr), mTimestamp(0) {}
WidevineDecryptedBlock::~WidevineDecryptedBlock() {
  if (mBuffer) {
    mBuffer->Destroy();
    mBuffer = nullptr;
  }
}

void WidevineDecryptedBlock::SetDecryptedBuffer(cdm::Buffer *buffer) {
  mBuffer = buffer;
}
cdm::Buffer *WidevineDecryptedBlock::DecryptedBuffer() { return mBuffer; }
void WidevineDecryptedBlock::SetTimestamp(int64_t timestamp) {
  mTimestamp = timestamp;
}
int64_t WidevineDecryptedBlock::Timestamp() const { return mTimestamp; }