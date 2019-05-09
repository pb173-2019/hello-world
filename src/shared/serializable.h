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
    namespace serialize {
        using structure = std::vector<unsigned char>;
    }
    namespace detail
    {
        template<typename T, typename = void>
        struct is_container : public std::false_type {};

        // std::void_t availible since c++17
        template<typename ... Args>
        struct container_helper {};

        template<typename T>
        struct is_container<
                T,
                std::conditional_t<false,
                        container_helper<
                                decltype(std::begin(std::declval<T>())),
                                decltype(std::end(std::declval<T>()))
                        >,
                        void
                >
        > : public std::true_type {};

    } // detail

    /**
     *  Interface for serializable objects
     * @tparam Obj inheritting class
     */
    template<typename Obj>
    struct Serializable {
        /**
         * serializes object
         * @param result where serialized object will be stored
         * @return reference to serialized object
         */
        virtual serialize::structure& serialize(serialize::structure& result) const = 0;

        /**
         * deseriliazes object from byte vector
         * @param data containing object
         * @param from position, where object starts (in data)
         * @return deserialized objec
         */
        static Obj deserialize(const serialize::structure& data, uint64_t& from) {
            return Obj::deserialize(data, from);
        }

        /**
         * seriliazes object to byte vector
         * (mainly for backward compatibility)
         * @return  serialized object
         */
        virtual serialize::structure serialize() const = 0;
        /**
         * deseriliazes object from byte vector
         * (mainly for backward compatibility)
         * @param data containing object
         * @return deserialized object
         */
        static Obj deserialize(const serialize::structure& data) {
            uint64_t from = 0;
            return Obj::deserialize(data, from);
        }
        virtual ~Serializable() = default;
    };

    namespace serialize {

        /**
         * typetrait allowing to use SFINAE for serializable object
         * if T is serializable contains value true otherwise false
         * @tparam T type of object to check
         */
        template<typename T>
        struct is_serializable : std::is_base_of<Serializable<T>, T> {
        };

        /**
         * serializes object, which inherits from Serializable
         * @tparam T type of object to serialize
         * @param obj object to serialize
         * @param result structure to store serialized object
         * @return reference to structure holding serialized object
         */
        template<typename T>
        auto serialize(const T &obj, serialize::structure &result)
        -> typename std::enable_if<is_serializable<T>::value, serialize::structure>::type {
            return obj.serialize(result);
        }

        /**
        * serializes object, which is a scalar type
        * @tparam T type of object to serialize
        * @param obj object to serialize
        * @param result structure to store serialized object
        * @return reference to structure holding serialized object
        */
        template<typename T>
        auto serialize(const T &obj, serialize::structure &result)
        -> typename std::enable_if<std::is_scalar<T>::value, serialize::structure>::type {
            union {
                unsigned char bytes[sizeof(T)];
                T value;
            } helper;
            helper.value = obj;
            for (auto i : helper.bytes) {
                result.push_back(i);
            }
            return result;
        }

        /**
        * serializes object, which is container
        * @tparam T type of object to serialize
        * @param obj object to serialize
        * @param result structure to store serialized object
        * @return reference to structure holding serialized object
        */
        template<typename T>
        auto serialize(const T &obj, serialize::structure &result)
        -> typename std::enable_if<detail::is_container<T>::value, serialize::structure>::type {
            uint64_t size = obj.size();
            serialize<uint64_t>(size, result);

            for (const auto &i : obj) {
                serialize(i, result);
            }
            return result;
        }

        /**
         * deserializes object, which is of scalar type
         * @tparam T type of object to deserialize
         * @param input structure holding serialized object
         * @param from offset where object starts in the structure
         * @return deserialized object
         */
        template<typename T>
        auto
        deserialize(const serialize::structure &input, uint64_t &from)
        -> typename std::enable_if<std::is_scalar<T>::value, T>::type {
            union {
                unsigned char bytes[sizeof(T)];
                T value;
            } helper;
            if (input.size() < from + sizeof(T)) {
                throw std::runtime_error("serialized data too short");
            }
            for (auto i = from; from < i + sizeof(T); ++from) {
                helper.bytes[from - i] = input[from];
            }
            return helper.value;
        }

        /**
         * deserializes object, which inherits from serializable
         * @tparam T type of object to deserialize
         * @param input structure holding serialized object
         * @param from offset where object starts in the structure
         * @return deserialized object
         */
        template<typename T>
        auto
        deserialize(const serialize::structure &input, uint64_t &from)
        -> typename std::enable_if<is_serializable<T>::value, T>::type {
            return Serializable<T>::deserialize(input, from);
        }

        /**
         * deserializes object, which is container
         * @tparam T type of object to deserialize
         * @param input structure holding serialized object
         * @param from offset where object starts in the structure
         * @return deserialized object
         */
        template<typename T, typename value_type = typename T::value_type>
        auto
        deserialize(const serialize::structure &input, uint64_t &from)
        -> typename std::enable_if<detail::is_container<T>::value, T>::type {
            T result;
            if (input.size() < sizeof(uint64_t)) {
                throw std::runtime_error("serialized data too short");
            }
            uint64_t size = deserialize<uint64_t>(input, from);
            for (uint64_t i = 0; i < size; ++i) {
                value_type tmp = deserialize<value_type>(input, from);
                result.push_back(std::move(tmp));
            }
            return result;
        }

    } // serialize
} // helloworld

#endif //HELLOWORLD_SHARED_SERIALIZABLE_H_
