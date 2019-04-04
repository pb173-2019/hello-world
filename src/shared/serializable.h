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

    template<typename Obj>
    struct Serializable {
        virtual serialize::structure& serialize(serialize::structure& result) const = 0;
        virtual serialize::structure serialize() const = 0;
        static Obj deserialize(const serialize::structure& data, uint64_t& from) {
            return Obj::deserialize(data, from);
        }
        static Obj deserialize(const serialize::structure& data) {
            uint64_t from = 0;
            return Obj::deserialize(data, from);
        }
        virtual ~Serializable() = default;
    };

    namespace serialize {

        template<typename T>
        struct is_serializable : std::is_base_of<Serializable<T>, T> {
        };


        template<typename T>
        auto serialize(const T &obj,
                       serialize::structure &result) -> typename std::enable_if<is_serializable<T>::value, serialize::structure>::type {
            return obj.serialize(result);
        }

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

        template<typename T>
        auto
        deserialize(const std::vector<unsigned char> &input, uint64_t &from)
        -> typename std::enable_if<std::is_scalar<T>::value, T>::type {
            union {
                unsigned char bytes[sizeof(T)];
                T value;
            } helper;
            for (auto i = from; from < i + sizeof(T); ++from) {
                helper.bytes[from - i] = input[from];
            }
            return helper.value;
        }

        template<typename T>
        auto
        deserialize(const std::vector<unsigned char> &input, uint64_t &from)
        -> typename std::enable_if<is_serializable<T>::value, T>::type {
            return Serializable<T>::deserialize(input, from);
        }

        template<typename T, typename value_type = typename T::value_type>
        auto
        deserialize(const std::vector<unsigned char> &input, uint64_t &from)
        -> typename std::enable_if<detail::is_container<T>::value, T>::type {
            T result;
            uint64_t size = deserialize<uint64_t>(input, from);
            for (uint64_t i = 0; i < size; ++i) {
                value_type tmp = deserialize<value_type>(input, from);
                result.push_back(std::move(tmp));
            }
            return result;
        }

    }
}

#endif //HELLOWORLD_SHARED_SERIALIZABLE_H_
