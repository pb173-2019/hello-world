/**
 * @file serializable.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief Serializable interface with supporting functionality to serialize data
 * @version 0.1
 * @date 16. 3. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_SERIALIZABLE_H_
#define HELLOWORLD_SHARED_SERIALIZABLE_H_

#include <vector>
#include <cstdint>

#include <iostream>

namespace helloworld {

template <typename Obj>
struct Serializable {
    virtual ~Serializable() = default;

    /**
     * Serialize Obj into unsigned char vector
     *
     * @return std::vector<unsigned int> serialized object
     */
    virtual std::vector<unsigned char> serialize() const = 0;

    /**
     * Obj has to implement its static getter
     * named deserialize with const std::vector<unsigned char>& as param
     *
     * @param data data to parse
     * @return Obj deserialized object
     */
    static Obj deserialize(const std::vector<unsigned char>& data) {
        return Obj::deserialize(data);
    };

    /**
     * Save numeric type value into output vector
     *
     * @tparam num numeric integral type
     * @param output output buffer to put data to
     * @param input data to process
     */
    template <typename num>
    static void addNumeric(std::vector<unsigned char>& output, const num& input) {
        int n = sizeof(input);
        for(int y = 0; n --> 0; y++)
            output.push_back((input >> (n*8)) & 0xFF);
    }

    /**
     * Inverse for addNumeric
     *
     * @tparam num numeric integral type
     * @param input input data buffer
     * @param from index in buffer where to start reading
     * @param output reference to value to fill
     * @return num of values read in bytes - equals to /position in / length of/ buffer
     */
    template <typename num>
    static uint64_t getNumeric(const std::vector<unsigned char>& input, uint64_t from, num& output) {
        output = 0;
        int n = sizeof(output);
        for(int y = 0; n --> 0; y++)
            output += (input[from + y] << (n*8));
        return sizeof(output);
    }

    /**
     * Save container type value into output vector
     * the input value must be of a primitive type, or at least have static length
     * 
     * !! this method works only for scalar inner value types
     * !! ignores endianity
     *
     * @tparam container container type supporting push_back() method, operator[] and size()
     * @param output output buffer
     * @param input input data container
     */
    template<typename container, typename value_type = typename container::value_type>
    static void addContainer(std::vector<unsigned char>& output, const container& input) {

        union {
            unsigned char bytes[sizeof(value_type)];
            value_type value;
        } data;

        addNumeric(output, input.size());
        for (uint64_t i = 0; i < input.size(); i++) {
            data.value = input[i];
            for (unsigned char c : data.bytes) {
                output.push_back(c);
            }
        }
    }
    /**
     * Inverse of addContainer
     *
     * @tparam container container type supporting push_back() method, operator[] and size()
     * @param input data buffer
     * @param from index in buffer where to start reading
     * @param output output container
     * @return num of values read in bytes
     */
    template<typename container, typename value_type = typename container::value_type>
    static uint64_t getContainer(const std::vector<unsigned char>& input, uint64_t from, container& output) {

        union {
            unsigned char bytes[sizeof(value_type)];
            value_type value;
        } data;

        uint64_t len = 0;
        uint64_t metadata = getNumeric(input, from, len);

        for (uint64_t i = 0; i < len; i++) {
            for (uint64_t ii = 0; ii < sizeof(value_type); ii++) {
                data.bytes[ii] = input[from + i * sizeof(value_type) + metadata + ii];
            }
            output.push_back(data.value);
        }

        return len + metadata;
    }

    /**
     * Save nested containers into buffer output, the inner container must be
     * applicable to getContainer() method
     * 
     * !! this method works only for the most inner value types with sizeof(unsigned char)
     *
     * @tparam container container type supporting push_back() method, operator[] and size()
     * @param output output buffer
     * @param input input data container
     */
    template <typename container, typename inner>
    static void addNestedContainer(std::vector<unsigned char>& output, const container& input) {
        addNumeric(output, input.size());
        for (uint64_t i = 0; i < input.size(); i++) {
            addContainer(output, input[i]);
        }
    }

    /**
     * Inverse of addNestedContainer
     *
     * @tparam container container type supporting push_back() method, operator[] and size()
     * @param input data buffer
     * @param from index in buffer where to start reading
     * @param output output container
     * @return num of values read in bytes
     */
    template <typename container, typename inner>
    static uint64_t getNestedContainer(const std::vector<unsigned char>& input, uint64_t from, container& output) {
        uint64_t len = 0;
        uint64_t metadata = getNumeric(input, from, len);
        for (uint64_t i = 0; i < len; i++) {
            inner tempContainer;
            metadata += getContainer(input, metadata, tempContainer);
            output.push_back(tempContainer);
        }
        return len + metadata;
    }
};

}

#endif //HELLOWORLD_SHARED_SERIALIZABLE_H_
