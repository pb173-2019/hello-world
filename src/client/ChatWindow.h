/**
 * @file ChatWindow.h
 * @author Adam Ivora (xivora@fi.muni.cz)
 * @brief chat window
 * @version 0.1
 * @date 2019-05-19
 *
 * @copyright Copyright (c) 2019
 *
 */
#ifndef HELLOWORLD_CLIENT_CHATWINDOW_H_
#define HELLOWORLD_CLIENT_CHATWINDOW_H_

#include <curses.h>
#include <string>

namespace helloworld {

/**
 * Creating an object of this class splits terminal horizontally. The top window
 * serves as a log and lines can be added by calling appendLine. This call is
 * non-blocking. The bottom window serves for user one-line input. User can
 * modify the input whatsoever until <return> is pressed. User input can be
 * obtained by calling getMessage. This call blocks until user presses <return>
 * key.
 *
 * After desctruction, terminal is reset to its original state.
 */
struct ChatWindow {
    ChatWindow() : line(1) {
        initscr();
        int maxx;
        getmaxyx(stdscr, maxy, maxx);

        top = newwin(maxy - 3, maxx, 0, 0);
        bottom = newwin(3, maxx, maxy - 3, 0);
        scrollok(top, TRUE);
        scrollok(bottom, TRUE);

        wsetscrreg(top, 1, maxy - 5);
        wsetscrreg(bottom, 1, maxy - 5);

        drawFrame();
    }

    ~ChatWindow() { endwin(); }

    void appendLine(const std::string& string) {
        mvwprintw(top, line, 2, string.c_str());

        if (line != maxy - 5)
            line++;
        else
            scroll(top);

        drawFrame();
        wrefresh(top);
    }

    std::string getMessage() {
        wrefresh(top);
        wrefresh(bottom);
        char str[256];
        mvwgetstr(bottom, 1, 2, str);
        wclear(bottom);
        drawFrame();
        appendLine(str);
        return str;
    }

   private:
    void drawFrame() {
        box(top, '|', '=');
        box(bottom, '|', '-');
    }

    WINDOW *top, *bottom;
    int maxy;
    int line;
};

}    // namespace helloworld

#endif    // HELLOWORLD_CLIENT_CHATWINDOW_H_
