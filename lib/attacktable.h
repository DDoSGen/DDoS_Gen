#pragma once
#include <map>
#include <string>

std::map<int, std::string> attacktable = {  {1, "TCP_SYN_ATTACK"},
                                            {2, "TCP_ACK_ATTACK"},
                                            {3, "TCP_SYN-ACK_ATTACK"},
                                            {4, "TCP_CONNECTION_ATTACK"},
                                            {5, "TCP_CONGESTION_CONTROL_ATTACK"},
                                            {6, "TCP_TSNAMI_ATTACK"},
                                            {7, "UDP_ATTACK"},
                                            {8, "ICMP_ATTACK"},
                                            {9, "GET_FLOODING_ATTACK"},
                                            {10, "POST_FLOODING_ATTACK"},
                                            {11, "DYNAMIC_HTTP_REQ_FLOODING"},
                                            {12, "SLOWLORIS_ATTACK"},
                                            {13, "SLOWREAD_ATTACK"},
                                            {14, "R-U-D-Y_ATTACK"},
                                            {15, "BIG1_ATTACK"}                 };

void print_attacktable();