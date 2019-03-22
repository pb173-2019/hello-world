/**
 * @file rrmanip.h
 * @author Ivan Mitruk (469063@mail.muni.cz)
 * @brief Parsers and Builders for requests and responses
 * @version 0.1
 * @date 2019-03-13
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_RRMANIP_H
#define HELLOWORLD_RRMANIP_H

#include "request.h"
#include "hmac.h"
#include <array>

namespace helloworld {

    /**
     * Super class
     */
    class RRManipualator {
    protected:
        HMAC authentificator;
    public:

        /**
        * @brief sets key for authentication
        *
        * @param new key which will be set for authentication
        */
        void setAuthenticationKey(std::vector<unsigned char> newKey);
    };

    /**
     * Super class
     */
    template<typename T>
    class RRBuilder : RRManipualator {
    protected:

        /**
        * @brief writes byte representation of header and payload
        *        into destination with their authentication data
        *
        * @param src header which will be written into destination
        * @param payload which will be written into destination
        * @param dest destination, where will byte representation
        *        written with its authentication data
        */
        void _writeTo(typename T::Header &src, std::vector<unsigned char> &payload, std::vector<unsigned char> &dest) {
            if (src.payloadLength > UINT32_MAX)
                throw std::runtime_error("Payload data too long.");

            dest.resize(sizeof(typename T::Header) + src.payloadLength);

            std::copy(&src, &src + 1, reinterpret_cast<typename T::Header *>(dest.data())); //NOLINT
            std::copy(payload.begin(), payload.end(), dest.data() + sizeof(typename T::Header));

            std::array<unsigned char, HMAC::hmac_size> hmac = RRManipualator::authentificator.generate(dest);
            std::copy(hmac.begin(), hmac.end(),
                      std::begin(reinterpret_cast<typename T::Header *>(dest.data())->hmac)); //NOLINT
        }
    };

    /**
     * Super class
     */
    template<typename T>
    class RRParser : RRManipualator {
    protected:

        /**
        * @brief reads header of message
        *
        * @param input stream, from which data will be read
        * @param dest header into which data will be loaded
        */
        void _readHeader(std::istream &input, typename T::Header &dest) {
            if (!input)
                throw std::runtime_error("Wrong input stream!");


            input.read(reinterpret_cast<char *>(&dest), sizeof(typename T::Header)); //NOLINT
            if (input.gcount() != sizeof(typename T::Header))
                throw std::runtime_error("Cannot read whole header!");
        }

        /**
        * @brief reads payload and autheticates whole message
        *
        * @param input stream, from which header will be read
        * @param header of message already set and validated
        * @param payload vector into which payload will be loaded
        */
        void _readPayload(std::istream &input, typename T::Header &header, std::vector<unsigned char> &payload) {
            if (!input)
                throw std::runtime_error("Wrong input stream!");


            payload.resize(header.payloadLength);
            input.read(reinterpret_cast<char *>(payload.data()), header.payloadLength); //NOLINT

            if (input.gcount() != header.payloadLength)
                throw std::runtime_error("Cannot read whole payload");


            std::array<unsigned char, HMAC::hmac_size> hmac;
            std::copy(std::begin(header.hmac), std::end(header.hmac), hmac.begin());
            std::fill(std::begin(header.hmac), std::end(header.hmac), 0u);

            std::vector<unsigned char> toAuth(sizeof(typename T::Header) + payload.size());
            std::copy(&header, &header + 1, reinterpret_cast<typename T::Header *>(toAuth.data()));
            std::copy(payload.begin(), payload.end(), toAuth.data() + sizeof(typename T::Header));
            if (hmac != authentificator.generate(toAuth))
                throw std::runtime_error("Authentification failed");

        }
    };

    class RequestBuilder : public RRBuilder<Request> {
        uint32_t lastMessageNumber;

    public:
        explicit RequestBuilder(uint32_t initialMessageNumber);

        /**
        * @brief sets request number for next message
        *
        * @param new number which is one less than message number set for next request
        */
        void setMessageNumber(uint32_t newNumber);

        /**
        * @brief writes authentificated byte representation into output stream, ready for encryption
        *
        * @param request which will be written into stream
        * @param output stream into which data will be written
        */
        void writeTo(Request &request, std::ostream &output);
    };

    class RequestParser : public RRParser<Request> {

        bool messageNumberSet;
        uint32_t expectedMessageNumber;
    public:
        explicit RequestParser();

        /**
        * @brief sets expected request number for next message
        *
        * @param new number expected from next message
        */
        void setMessageNumber(uint32_t newNumber);


        /**
        * @brief parses request from input stream and verifies it
        *
        * @param input stream from which is request parsed
        * @return parsed request
        */
        Request parseRequest(std::istream &input);
    };


    class ResponseBuilder : public RRBuilder<Response> {
    public:
        /**
        * @brief writes authenticated byte representation into output stream, ready for encryption
        *
        * @param request which will be written into stream
        * @param output stream into which data will be written
        */
        void writeTo(Response &response, std::ostream &output);
    };

    class ResponseParser : public RRParser<Response> {
    public:
        /**
        * @brief parses response from input stream and verifies it
        *
        * @param input stream from which is response parsed
        * @return parsed response
        */
        Response parseResponse(std::istream &input);
    };


}; // namespace helloworld
#endif //HELLOWORLD_RRMANIP_H
