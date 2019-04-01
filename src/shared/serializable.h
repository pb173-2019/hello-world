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
#include <type_traits>
#include <iostream>
#include <cassert>

namespace helloworld {
    namespace detail {
        template<typename T, typename _ = void>
        struct is_container : std::false_type {};

        template<typename... Ts>
        struct is_container_helper {};


        template<typename T>
        struct is_container<
                T,
                std::conditional_t<
                        false,
                        is_container_helper<
                                decltype(std::end(std::declval<T>())),
                                decltype(std::begin(std::declval<T>()))
                        >,
                        void
                >
        > : public std::true_type {};

        template<typename T, typename = void>
        struct has_static_storage : std::true_type {};

        template<typename T>
        struct has_static_storage<
                T,
                std::conditional_t<
                        false,
                        std::void_t<
                                decltype(std::declval<T>().push_back(*std::declval<T>().begin()))
                        >,
                        void
                >
        > : public std::false_type {};

        template<class T, size_t N>
        uint64_t size(T (&)[N]) { return N; }

        template<class T>
        auto size(const T& container) -> typename std::enable_if< is_container<T>::value, uint64_t >::type { return container.size(); }
    }
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
     *for (uint64_t i = 0; i < len; i++)
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
     * the input value must be of a primitive type
     * 
     * !! this method works only for scalar inner value types
     * !! ignores endianity
     *
     * @tparam container container type supporting push_back() method, operator[] and size()
     * @param output output buffer
     * @param input input data container
     */
    template<typename container>
    static auto addContainer(std::vector<unsigned char>& output, const container& input) ->
    typename std::enable_if< detail::is_container<container>::value, void >::type
    {

        using value_type = std::remove_cv_t<std::remove_reference_t<decltype(*std::begin(input))> >;

        union {
            unsigned char bytes[sizeof(value_type)];
            value_type value;
        } data;

        addNumeric(output, detail::size(input));
        auto __begin = std::begin(input);
        auto __end = std::end(input);
        for (; __begin != __end; ++__begin) {
            data.value = *__begin;
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
    template<typename container>
    static auto getContainer(const std::vector<unsigned char>& input, uint64_t from, container& output)
    -> typename std::enable_if<detail::is_container<container>::value && !detail::has_static_storage<container>::value, uint64_t >::type {

        using value_type = std::remove_cv_t<std::remove_reference_t<decltype(*std::begin(output))> >;

        union {
            unsigned char bytes[sizeof(value_type)];
            value_type value;
        } data;

        uint64_t len = 0;
        uint64_t metadata = getNumeric(input, from, len);

        for (uint64_t i = 0; i < len; ++i) {
            for (uint64_t ii = 0; ii < sizeof(value_type); ii++) {
                data.bytes[ii] = input[from + i * sizeof(value_type) + metadata + ii];
            }
            output.push_back(data.value);
        }

        return len + metadata;
    }

    /**
    * Inverse of addContainer for container not supporting pushback
    *
    * @tparam container container type supporting push_back() method, operator[] and size()
    * @param input data buffer
    * @param from index in buffer where to start reading
    * @param output output container
    * @return num of values read in bytes
    */
    template<typename container>
    static auto getContainer(const std::vector<unsigned char>& input, uint64_t from, container& output)
    -> typename std::enable_if<detail::is_container<container>::value && detail::has_static_storage<container>::value, uint64_t >::type {

        using value_type = std::remove_cv_t<std::remove_reference_t<decltype(*std::begin(output))> >;

        union {
            unsigned char bytes[sizeof(value_type)];
            value_type value;
        } data;

        uint64_t len = 0;
        uint64_t metadata = getNumeric(input, from, len);

        assert(len == detail::size(output));

        auto outputBegin = output.begin;

        for (uint64_t i = 0; i < len; ++i, ++outputBegin) {
            for (uint64_t ii = 0; ii < sizeof(value_type); ii++) {
                data.bytes[ii] = input[from + i * sizeof(value_type) + metadata + ii];
            }
            *outputBegin = data.value;
        }

        return len + metadata;
    }
    /**
     * Save nested containers into buffer output, the inner container must be
     * applicable to getContainer() method
     * 
     * !! this method works only for container that
     *    contains values serializable with addContainer() method
     *
     * @tparam container container type supporting push_back() method, operator[] and size()
     * @param output output buffer
     * @param input input data container
     */
    template <typename container, typename inner = typename std::remove_cv_t<std::remove_reference_t<decltype(*std::begin(std::declval<container>()))> > >
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
    template <typename container, typename inner = typename std::remove_cv_t<std::remove_reference_t<decltype(*std::begin(std::declval<container>()))> > >
    static uint64_t getNestedContainer(const std::vector<unsigned char>& input, uint64_t from, container& output) {
        uint64_t len = 0;
        uint64_t metadata = getNumeric(input, from, len);

        for (uint64_t i = 0; i < len; i++) {
            inner tempContainer;
            metadata += getContainer(input, metadata + from, tempContainer);
            output.push_back(tempContainer);
        }
        return len + metadata;
    }
};

}

#endif //HELLOWORLD_SHARED_SERIALIZABLE_H_
