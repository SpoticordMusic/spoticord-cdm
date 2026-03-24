#pragma once

#include "cdm/content_decryption_module.h"

class WidevineAdapter : public cdm::Host_11 {
public:
  WidevineAdapter(void *context);
  ~WidevineAdapter() override;

  cdm::Buffer *Allocate(uint32_t capacity) override;
  void SetTimer(int64_t delay_ms, void *context) override;
  cdm::Time GetCurrentWallTime() override;
  void OnResolveNewSessionPromise(uint32_t promise_id, const char *session_id,
                                  uint32_t session_id_size) override;
  void OnResolvePromise(uint32_t promise_id) override;
  void OnRejectPromise(uint32_t promise_id, cdm::Exception exception,
                       uint32_t system_code, const char *error_message,
                       uint32_t error_message_size) override;
  void OnSessionMessage(const char *session_id, uint32_t session_id_size,
                        cdm::MessageType message_type, const char *message,
                        uint32_t message_size) override;
  void OnSessionKeysChange(const char *session_id, uint32_t session_id_size,
                           bool has_additional_usable_key,
                           const cdm::KeyInformation *keys_info,
                           uint32_t keys_info_count) override;
  void OnSessionClosed(const char *session_id,
                       uint32_t session_id_size) override;
  void SendPlatformChallenge(const char *service_id, uint32_t service_id_size,
                             const char *challenge,
                             uint32_t challenge_size) override;
  void EnableOutputProtection(uint32_t desired_protection_mask) override;
  void QueryOutputProtectionStatus() override;
  void OnDeferredInitializationDone(cdm::StreamType stream_type,
                                    cdm::Status decoder_status) override;
  void OnExpirationChange(const char *session_id, uint32_t session_id_size,
                          cdm::Time new_expiry_time) override;
  void OnInitialized(bool success) override;
  void OnResolveKeyStatusPromise(uint32_t promise_id,
                                 cdm::KeyStatus key_status) override;
  void ReportMetrics(cdm::MetricName metric_name, uint64_t value) override;
  void RequestStorageId(uint32_t version) override;
  cdm::FileIO *CreateFileIO(cdm::FileIOClient *client) override;

private:
  void *context_ = nullptr;
};

class WidevineBuffer : public cdm::Buffer {
public:
  explicit WidevineBuffer(uint32_t aSize);
  ~WidevineBuffer() override;
  void Destroy() override;
  uint32_t Capacity() const override;
  uint8_t *Data() override;
  void SetSize(uint32_t aSize) override;
  uint32_t Size() const override;

private:
  uint8_t *buffer_ = nullptr;
  uint32_t bufferCapacity_ = 0;
  uint32_t bufferSize_ = 0;
};

class WidevineDecryptedBlock : public cdm::DecryptedBlock {
public:
  WidevineDecryptedBlock();
  ~WidevineDecryptedBlock() override;
  void SetDecryptedBuffer(cdm::Buffer *buffer) override;
  cdm::Buffer *DecryptedBuffer() override;
  void SetTimestamp(int64_t timestamp) override;
  int64_t Timestamp() const override;

private:
  cdm::Buffer *mBuffer;
  int64_t mTimestamp;
};