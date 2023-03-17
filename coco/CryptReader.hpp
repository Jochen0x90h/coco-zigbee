#pragma once

#include "crypt.hpp"
#include "Nonce.hpp"
#include <coco/BufferReader.hpp>
#include <coco/String.hpp>


namespace coco {

class CryptReader : public BufferReader {
public:

	CryptReader() = default;
	CryptReader(uint8_t *message, uint8_t *end) : BufferReader(message, end) {}
	CryptReader(uint8_t *message, int length) : BufferReader(message, length) {}
	CryptReader(Buffer &buffer) : BufferReader(buffer) {}

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
	 * Set start of message at given position
	 */
	void setMessageFromEnd(int offset) {this->message = this->end - offset;}

	/**
	 * Decrypt in-place, call after header has been read
	 */
	bool decrypt(int micLength, Nonce const &nonce, AesKey const &aesKey) {
		auto header = this->header;
		auto message = this->message;
		assert(header != nullptr);
		assert(message != nullptr);
		auto mic = this->end - micLength;
		int headerLength = message - header;
		int payloadLength = mic - message; // is zero when only the mic is present

		// cut off message integrity code
		this->end -= micLength;

		// encrypt in-place
		return coco::decrypt(message, header, headerLength, message, payloadLength, micLength, nonce, aesKey);
	}

protected:

	uint8_t const *header = nullptr;
	uint8_t *message = nullptr;
};

} // namespace coco
