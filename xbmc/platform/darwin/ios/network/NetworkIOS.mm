/*
 *  Copyright (C) 2005-2018 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#include "NetworkIOS.h"

#include "Util.h"
#include "utils/StringUtils.h"
#include "utils/log.h"

#include "platform/darwin/ios/network/ioshacks.h"

#include <cstdlib>
#include <errno.h>

#include <arpa/inet.h>
#include <dns.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <resolv.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sockio.h>

#include "PlatformDefs.h"


CNetworkInterfaceIOS::CNetworkInterfaceIOS(CNetworkIOS* network, std::string interfaceName, char interfaceMacAddrRaw[6])
  : m_interfaceName(interfaceName)
  , m_interfaceMacAdr(StringUtils::Format("%02X:%02X:%02X:%02X:%02X:%02X",
                                          static_cast<uint8_t>(interfaceMacAddrRaw[0]),
                                          static_cast<uint8_t>(interfaceMacAddrRaw[1]),
                                          static_cast<uint8_t>(interfaceMacAddrRaw[2]),
                                          static_cast<uint8_t>(interfaceMacAddrRaw[3]),
                                          static_cast<uint8_t>(interfaceMacAddrRaw[4]),
                                          static_cast<uint8_t>(interfaceMacAddrRaw[5])))
{
  m_network = network;
  memcpy(m_interfaceMacAddrRaw, interfaceMacAddrRaw, sizeof(m_interfaceMacAddrRaw));
}

CNetworkInterfaceIOS::~CNetworkInterfaceIOS(void) = default;

const std::string& CNetworkInterfaceIOS::GetName(void) const
{
  return m_interfaceName;
}

bool CNetworkInterfaceIOS::IsEnabled() const
{
  struct ifreq ifr;
  strcpy(ifr.ifr_name, m_interfaceName.c_str());
  if (ioctl(m_network->GetSocket(), SIOCGIFFLAGS, &ifr) < 0)
    return false;

  return ((ifr.ifr_flags & IFF_UP) == IFF_UP);
}

bool CNetworkInterfaceIOS::IsConnected() const
{
  struct ifreq ifr;
  memset(&ifr, 0, sizeof(struct ifreq));
  strcpy(ifr.ifr_name, m_interfaceName.c_str());
  if (ioctl(m_network->GetSocket(), SIOCGIFFLAGS, &ifr) < 0)
    return false;

  // ignore loopback
  int iRunning = ((ifr.ifr_flags & IFF_RUNNING) && (!(ifr.ifr_flags & IFF_LOOPBACK)));

  if (ioctl(m_network->GetSocket(), SIOCGIFADDR, &ifr) < 0)
    return false;

  // return only interfaces which has ip address
  int zero = 0;
  return iRunning && (0 != memcmp(ifr.ifr_addr.sa_data + sizeof(short), &zero, sizeof(int)));
}

std::string CNetworkInterfaceIOS::GetMacAddress() const
{
  return m_interfaceMacAdr;
}

void CNetworkInterfaceIOS::GetMacAddressRaw(char rawMac[6]) const
{
  memcpy(rawMac, m_interfaceMacAddrRaw, 6);
}

std::string CNetworkInterfaceIOS::GetCurrentIPAddress(void) const
{
  std::string result;

  struct ifreq ifr;
  strcpy(ifr.ifr_name, m_interfaceName.c_str());
  ifr.ifr_addr.sa_family = AF_INET;
  if (ioctl(m_network->GetSocket(), SIOCGIFADDR, &ifr) >= 0)
  {
    result = inet_ntoa((*(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr))).sin_addr);
  }

  return result;
}

std::string CNetworkInterfaceIOS::GetCurrentNetmask(void) const
{
  std::string result;

  struct ifreq ifr;
  strcpy(ifr.ifr_name, m_interfaceName.c_str());
  ifr.ifr_addr.sa_family = AF_INET;
  if (ioctl(m_network->GetSocket(), SIOCGIFNETMASK, &ifr) >= 0)
  {
    result = inet_ntoa((*(reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr))).sin_addr);
  }

  return result;
}

std::string CNetworkInterfaceIOS::GetCurrentDefaultGateway(void) const
{
  std::string result;

  FILE* pipe = popen("echo \"show State:/Network/Global/IPv4\" | scutil | grep Router", "r");
  usleep(100000);
  if (pipe)
  {
    char buffer[256] = {'\0'};
    if (fread(buffer, sizeof(char), sizeof(buffer), pipe) > 0 && !ferror(pipe))
    {
      std::string tmpStr = buffer;
      if (tmpStr.length() >= 11)
        result = tmpStr.substr(11);
    }
    pclose(pipe);
  }
  if (result.empty())
    CLog::Log(LOGWARNING, "Unable to determine gateway");

  return result;
}

CNetworkIOS::CNetworkIOS()
  : CNetworkBase()
{
  m_sock = socket(AF_INET, SOCK_DGRAM, 0);
  queryInterfaceList();
}

CNetworkIOS::~CNetworkIOS(void)
{
  if (m_sock != -1)
    close(CNetworkIOS::m_sock);

  std::vector<CNetworkInterface*>::iterator it = m_interfaces.begin();
  while (it != m_interfaces.end())
  {
    CNetworkInterface* nInt = *it;
    delete nInt;
    it = m_interfaces.erase(it);
  }
}

std::vector<CNetworkInterface*>& CNetworkIOS::GetInterfaceList(void)
{
  return m_interfaces;
}

//! @bug
//! Overwrite the GetFirstConnectedInterface and requery
//! the interface list if no connected device is found
//! this fixes a bug when no network is available after first start of xbmc
//! and the interface comes up during runtime
CNetworkInterface* CNetworkIOS::GetFirstConnectedInterface(void)
{
  CNetworkInterface* pNetIf = CNetworkBase::GetFirstConnectedInterface();

  // no connected Interfaces found? - requeryInterfaceList
  if (!pNetIf)
  {
    CLog::Log(LOGDEBUG, "%s no connected interface found - requery list", __FUNCTION__);
    queryInterfaceList();
    //retry finding a connected if
    pNetIf = CNetworkBase::GetFirstConnectedInterface();
  }

  return pNetIf;
}

void CNetworkIOS::GetMacAddress(const std::string& interfaceName, char rawMac[6])
{
  memset(rawMac, 0, 6);

#if !defined(IFT_ETHER)
#define IFT_ETHER 0x6 /* Ethernet CSMACD */
#endif
  // Query the list of interfaces.
  struct ifaddrs* list;

  if (getifaddrs(&list) < 0)
  {
    return;
  }

  for (struct ifaddrs* interface = list; interface != nullptr; interface = interface->ifa_next)
  {
    if (interfaceName == interface->ifa_name)
    {
      if ((interface->ifa_addr->sa_family == AF_LINK) && ((reinterpret_cast<const struct sockaddr_dl*>(interface->ifa_addr))->sdl_type == IFT_ETHER))
      {
        const struct sockaddr_dl* dlAddr = reinterpret_cast<const struct sockaddr_dl*>(interface->ifa_addr);
        const uint8_t* base = reinterpret_cast<const uint8_t*>(&dlAddr->sdl_data[dlAddr->sdl_nlen]);

        if (dlAddr->sdl_alen > 5)
        {
          memcpy(rawMac, base, 6);
        }
      }
      break;
    }
  }

  freeifaddrs(list);
}

void CNetworkIOS::queryInterfaceList()
{
  m_interfaces.clear();

  // Query the list of interfaces.
  struct ifaddrs* list;
  if (getifaddrs(&list) < 0)
    return;

  for (struct ifaddrs* cur = list; cur != nullptr; cur = cur->ifa_next)
  {
    if (cur->ifa_addr->sa_family != AF_INET)
      continue;

    char macAddrRaw[6];
    GetMacAddress(cur->ifa_name, macAddrRaw);

    // only add interfaces with non-zero mac addresses
    if (macAddrRaw[0] || macAddrRaw[1] || macAddrRaw[2] || macAddrRaw[3] || macAddrRaw[4] || macAddrRaw[5])
      // Add the interface.
      m_interfaces.push_back(new CNetworkInterfaceIOS(this, cur->ifa_name, macAddrRaw));
  }

  freeifaddrs(list);
}

std::vector<std::string> CNetworkIOS::GetNameServers(void)
{
  std::vector<std::string> nameServers;

  res_state res = static_cast<res_state>(malloc(sizeof(struct __res_state)));

  int result = res_ninit(res);

  if (result == 0)
  {
    for (int i = 0; i < res->nscount; i++)
    {
      std::string s = inet_ntoa(res->nsaddr_list[i].sin_addr);
      nameServers.push_back(s);
    }
  }
  else
  {
    CLog::Log(LOGERROR, "CNetworkIOS::GetNameServers - no nameservers could be fetched (error %d)", result);
  }

  free(res);
  return nameServers;
}

bool CNetworkIOS::PingHost(unsigned long remote_ip, unsigned int timeout_ms)
{
  return false;
}

bool CNetworkInterfaceIOS::GetHostMacAddress(unsigned long host_ip, std::string& mac) const
{
  bool ret = false;
  size_t needed;
  int mib[6];

  mac = "";

  mib[0] = CTL_NET;
  mib[1] = PF_ROUTE;
  mib[2] = 0;
  mib[3] = AF_INET;
  mib[4] = NET_RT_FLAGS;
  mib[5] = RTF_LLINFO;

  if (sysctl(mib, ARRAY_SIZE(mib), NULL, &needed, NULL, 0) == 0)
  {
    char* buf = static_cast<char*>(malloc(needed));
    if (buf)
    {
      if (sysctl(mib, ARRAY_SIZE(mib), buf, &needed, NULL, 0) == 0)
      {
        struct rt_msghdr* rtm;
        for (char* next = buf; next < buf + needed; next += rtm->rtm_msglen)
        {

          rtm = reinterpret_cast<struct rt_msghdr*>(next);
          struct sockaddr_inarp* sin = reinterpret_cast<struct sockaddr_inarp*>(rtm + 1);
          struct sockaddr_dl* sdl = reinterpret_cast<struct sockaddr_dl*>(sin + 1);

          if (host_ip != sin->sin_addr.s_addr || sdl->sdl_alen < 6)
            continue;

          u_char* cp = (u_char*)LLADDR(sdl);

          mac = StringUtils::Format("%02X:%02X:%02X:%02X:%02X:%02X",
                                    cp[0], cp[1], cp[2], cp[3], cp[4], cp[5]);
          ret = true;
          break;
        }
      }
      free(buf);
    }
  }
  return ret;
}
