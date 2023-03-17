#pragma once

#include "crypt.hpp"
#include "Nonce.hpp"
#include <coco/BufferWriter.hpp>
#include <coco/DataBuffer.hpp>
#include <coco/Array.hpp>
#include <coco/String.hpp>


namespace coco {

class CryptWriter : public BufferWriter {
public:
	CryptWriter() = default;
	CryptWriter(uint8_t *begin, uint8_t *end) : BufferWriter(begin, end) {}
	CryptWriter(uint8_t *data, int length) : BufferWriter(data, length) {}
	template <typename T>
	CryptWriter(T &buffer) : CryptWriter(std::data(buffer), std::size(buffer)) {}
	template <typename T>
	CryptWriter(T &&buffer) : CryptWriter(std::data(buffer), std::size(buffer)) {}

	/**
	 * Set start of header at current position ("string a" for encryption)
	 */
	void setHeader() {this->header = this->current;}

	/**
	 * Set start of header at given position ("string a" for encryption)
	 */
	void setHeader(uint8_t const *header) {this->header = header;}

	/**
	 * Set start of message at current position
	 */
	void setMessage() {this->message = this->current;}

	/**
	 * Encrypt in-place, call after message has been written
	 */
	void encrypt(int micLength, Nonce const &nonce, AesKey const &aesKey) {
		auto header = this->header;
		auto message = this->message;
		assert(header != nullptr);
		assert(message != nullptr);
		int headerLength = message - header;
		int payloadLength = this->current - message;
		this->skip(micLength);

		// encrypt in-place
		coco::encrypt(message, header, headerLength, message, payloadLength, micLength, nonce, aesKey);
	}

protected:

	uint8_t const *header = nullptr;
	uint8_t *message = nullptr;
};

} // namespace coco
