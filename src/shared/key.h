/**
 * @file key.h
 * @author Jiří Horák (469130@mail.muni.cz)
 * @brief
 * @version 0.1
 * @date 7. 5. 2019
 *
 * @copyright Copyright (c) 2019
 *
 */

#ifndef HELLOWORLD_SHARED_KEY_H_
#define HELLOWORLD_SHARED_KEY_H_

#include <memory>
#include <vector>
#include <cstring>

#include <cstdlib>
#include <new>
#include <iostream>

namespace helloworld {
    namespace zero {

//template<class T>
//struct KeyAlloc : public std::allocator<T> {
//    using value_type = T;
//
//    KeyAlloc() = default;
//
//    template<class U>
//    constexpr KeyAlloc(const KeyAlloc<U> &) noexcept {}
//
//    template<class U>
//    KeyAlloc(KeyAlloc<U> &&) noexcept {}
//
//    template<class U>
//    KeyAlloc&operator=(KeyAlloc<U> &&) {
//        return *this;
//    }
//
//    T *allocate(std::size_t n) {
//        return std::allocator<T>::allocate(n);
//    }
//
//    void deallocate(T *p, std::size_t n) noexcept {
//        std::memset(p, 0, n);
//        return std::allocator<T>::deallocate(p, n);
//    }
//};

        template<class T>
        struct KeyAlloc {
            using value_type = T;

            KeyAlloc() = default;

            template<class U>
            constexpr KeyAlloc(const KeyAlloc<U> &) noexcept {}

            T *allocate(std::size_t n) {
                if (n > std::size_t(-1) / sizeof(T)) throw std::bad_alloc();
                if (auto p = static_cast<T *>(std::malloc(n * sizeof(T)))) return p;
                throw std::bad_alloc();
            }

            void deallocate(T *p, std::size_t n) noexcept {
                std::memset(p, 0, n);
                std::free(p);
            }
        };

        template<class T, class U>
        bool operator==(const KeyAlloc<T> &, const KeyAlloc<U> &) { return true; }

        template<class T, class U>
        bool operator!=(const KeyAlloc<T> &, const KeyAlloc<U> &) { return false; }


//        template <typename Inner, template <typename> class Container>
//        class Zeroizer {
//            Container<Inner> c{};
//
//        public:
//            Zeroizer() = default;
//            Zeroizer(const Zeroizer& other) : c(other.c) {}
//            Zeroizer(Zeroizer&& other) {
//                auto* ptr = other.c.data();
//                size_t length = other.c.size();
//                std::swap(c, other.c);
//                std::memset(ptr, 0, length);
//            }
//            Zeroizer&operator=(const Zeroizer& other) {
//                c = other.c;
//                return *this;
//            }
//            Zeroizer&operator=(Zeroizer&& other) {
//                auto* ptr = other.c.data();
//                size_t length = other.c.size();
//                std::swap(c, other.c);
//                std::memset(ptr, 0, length);
//                return *this;
//            }
//            ~Zeroizer() {
//                std::memset(c.data(), 0, c.size());
//            }
//
//            const Inner& at(size_t idx) const { return c.at(idx); }
//            Inner&operator[](size_t idx) { return c[idx]; }
//            const Inner&operator[](size_t idx) const { return c[idx]; }
//
//            Inner& front() { return c.front(); }
//            const Inner& front() const { return c.front(); }
//            Inner& back() { return c.back(); }
//            const Inner& back() const { return c.back(); }
//            Inner* data() { return c.data(); }
//            const Inner* data() const { return c.data(); }
//
//            size_t size() const { return c.size(); }
//            Inner& at(size_t idx) { return c.at(idx); }
//
//            Container<Inner>::iterator begin() {
//                return c.begin();
//            }
//
//
//
//
//        };
//
//        template <typename Inner, template <typename> class Container>
//        bool operator==(const Zeroizer<Inner, Container> &a, const Zeroizer<Inner, Container> &b) {
//            return a.c == b.c;
//        }
//
//        template <typename Inner, template <typename> class Container>
//        bool operator!=(const Zeroizer<Inner, Container> &a, const Zeroizer<Inner, Container> &b) {
//            return !(a==b);
//        }

        using bytes_t = std::vector<unsigned char, KeyAlloc<unsigned char>>;
        using str_t = std::basic_string<char, std::char_traits<char>, KeyAlloc<char>>;

        str_t to_hex(const bytes_t &bytes);

        bytes_t from_hex(const str_t &input);

        void write_n(std::ostream &out, const str_t &data);

        void write_n(std::ostream &out, const bytes_t &data);

        /**
         * Split key functions
         */
        std::pair<bytes_t, bytes_t> split(bytes_t first, size_t index);

        std::pair<bytes_t, bytes_t> split(const bytes_t &input);

        template<typename T>
        std::pair<bytes_t, std::vector<T>> split(bytes_t first, size_t index) {
            std::vector<T> second(first.begin() + index, first.end());
            first.resize(first.size() - second.size());
            return std::make_pair(first, second);
        }

        template<typename T>
        std::pair<std::vector<T>, bytes_t> split(std::vector<T> first, size_t index) {
            bytes_t second(first.begin() + index, first.end());
            first.resize(first.size() - second.size());
            return std::make_pair(first, second);
        }

        template<typename T>
        std::pair<bytes_t, std::vector<T>> split(const bytes_t &input) {
            return split(input, input.size() / 2);
        }

    } // namespace zero
} // namespace helloworld

#endif //HELLOWORLD_SHARED_KEY_H_
