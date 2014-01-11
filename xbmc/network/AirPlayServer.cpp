/*
 * Many concepts and protocol specification in this code are taken
 * from Airplayer. https://github.com/PascalW/Airplayer
 *
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2.1, or (at your option)
 *  any later version.
 *
 *  This Program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */

#include "network/Network.h"
#include "AirPlayServer.h"

#ifdef HAS_AIRPLAY

#include <netinet/in.h>
#include <arpa/inet.h>
#include "DllLibPlist.h"
#include "utils/log.h"
#include "utils/URIUtils.h"
#include "utils/StringUtils.h"
#include "threads/SingleLock.h"
#include "filesystem/File.h"
#include "filesystem/Directory.h"
#include "FileItem.h"
#include "Application.h"
#include "ApplicationMessenger.h"
#include "utils/md5.h"
#include "utils/Variant.h"
#include "settings/Settings.h"
#include "guilib/Key.h"
#include "URL.h"
#include "cores/IPlayer.h"
#include "interfaces/AnnouncementManager.h"
#include "profiles/ProfilesManager.h"
#include "utils/XBMCTinyXML.h"

using namespace ANNOUNCEMENT;

#ifdef TARGET_WINDOWS
#define close closesocket
#endif

#define RECEIVEBUFFER 1024

#define AIRPLAY_STATUS_OK                  200
#define AIRPLAY_STATUS_SWITCHING_PROTOCOLS 101
#define AIRPLAY_STATUS_NEED_AUTH           401
#define AIRPLAY_STATUS_NOT_FOUND           404
#define AIRPLAY_STATUS_METHOD_NOT_ALLOWED  405
#define AIRPLAY_STATUS_PRECONDITION_FAILED 412
#define AIRPLAY_STATUS_NOT_IMPLEMENTED     501
#define AIRPLAY_STATUS_NO_RESPONSE_NEEDED  1000

CAirPlayServer *CAirPlayServer::ServerInstance = NULL;
int CAirPlayServer::m_isPlaying = 0;

#define EVENT_NONE     -1
#define EVENT_PLAYING   0
#define EVENT_PAUSED    1
#define EVENT_LOADING   2
#define EVENT_STOPPED   3
const char *eventStrings[] = {"playing", "paused", "loading", "stopped"};

#define PLAYBACK_INFO  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"\
"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\r\n"\
"<plist version=\"1.0\">\r\n"\
"<dict>\r\n"\
"<key>duration</key>\r\n"\
"<real>%f</real>\r\n"\
"<key>loadedTimeRanges</key>\r\n"\
"<array>\r\n"\
"\t\t<dict>\r\n"\
"\t\t\t<key>duration</key>\r\n"\
"\t\t\t<real>%f</real>\r\n"\
"\t\t\t<key>start</key>\r\n"\
"\t\t\t<real>0.0</real>\r\n"\
"\t\t</dict>\r\n"\
"</array>\r\n"\
"<key>playbackBufferEmpty</key>\r\n"\
"<true/>\r\n"\
"<key>playbackBufferFull</key>\r\n"\
"<false/>\r\n"\
"<key>playbackLikelyToKeepUp</key>\r\n"\
"<true/>\r\n"\
"<key>position</key>\r\n"\
"<real>%f</real>\r\n"\
"<key>rate</key>\r\n"\
"<real>%d</real>\r\n"\
"<key>readyToPlay</key>\r\n"\
"<true/>\r\n"\
"<key>seekableTimeRanges</key>\r\n"\
"<array>\r\n"\
"\t\t<dict>\r\n"\
"\t\t\t<key>duration</key>\r\n"\
"\t\t\t<real>%f</real>\r\n"\
"\t\t\t<key>start</key>\r\n"\
"\t\t\t<real>0.0</real>\r\n"\
"\t\t</dict>\r\n"\
"</array>\r\n"\
"</dict>\r\n"\
"</plist>\r\n"

#define PLAYBACK_INFO_NOT_READY  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"\
"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\r\n"\
"<plist version=\"1.0\">\r\n"\
"<dict>\r\n"\
"<key>readyToPlay</key>\r\n"\
"<false/>\r\n"\
"</dict>\r\n"\
"</plist>\r\n"

#define SERVER_INFO  "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"\
"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\r\n"\
"<plist version=\"1.0\">\r\n"\
"<dict>\r\n"\
"<key>deviceid</key>\r\n"\
"<string>%s</string>\r\n"\
"<key>features</key>\r\n"\
"<integer>%s</integer>\r\n"\
"<key>model</key>\r\n"\
"<string>%s</string>\r\n"\
"<key>protovers</key>\r\n"\
"<string>1.0</string>\r\n"\
"<key>srcvers</key>\r\n"\
"<string>%s</string>\r\n"\
"</dict>\r\n"\
"</plist>\r\n"

#define EVENT_INFO "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\r\n"\
"<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\r\n"\
"<plist version=\"1.0\">\r\n"\
"<dict>\r\n"\
"<key>category</key>\r\n"\
"<string>video</string>\r\n"\
"<key>sessionID</key>\r\n"\
"<integer>%d</integer>\r\n"\
"<key>state</key>\r\n"\
"<string>%s</string>\r\n"\
"</dict>\r\n"\
"</plist>\r\n"\

#define AUTH_REALM "AirPlay"
#define AUTH_REQUIRED "WWW-Authenticate: Digest realm=\""  AUTH_REALM  "\", nonce=\"%s\"\r\n"

static CStdString srvvers = AIRPLAY_SERVER_VERSION_STR;
static CStdString srvname = "Xbmc,1";
static CStdString srvfeatures = "119";
static CStdString macAdr;
static CStdString featuresProtocol = "119";

void CAirPlayServer::Announce(AnnouncementFlag flag, const char *sender, const char *message, const CVariant &data)
{
  if ( (flag & Player) && strcmp(sender, "xbmc") == 0 && ServerInstance)
  {
    if (strcmp(message, "OnStop") == 0)
    {
      restoreVolume();
      ServerInstance->AnnounceToClients(EVENT_STOPPED);
    }
    else if (strcmp(message, "OnPlay") == 0)
    {
      ServerInstance->AnnounceToClients(EVENT_PLAYING);
    }
    else if (strcmp(message, "OnPause") == 0)
    {
      ServerInstance->AnnounceToClients(EVENT_PAUSED);
    }
  }
}

bool CAirPlayServer::StartServer(int port, bool nonlocal)
{
  StopServer(true);

  CStdString srvVers, features, serviceName, mac, featuresprotocol;
  LoadAnnouncementFromXml(srvVers, features, serviceName, mac, featuresprotocol);
  if (srvVers.length())
    srvvers = srvVers;
  if (features.length())
  {
    unsigned long featuredec = strtoul(features.c_str(),NULL,16);
    srvfeatures = StringUtils::Format("%d",featuredec);
  }
  if (serviceName.length())
    srvname = serviceName;
  if (mac.length())
    macAdr = mac;
  else
    macAdr = g_application.getNetwork().GetFirstConnectedInterface()->GetMacAddress();
  
  if (featuresprotocol.length())
    featuresProtocol = featuresprotocol;
  
  ServerInstance = new CAirPlayServer(port, nonlocal);
  if (ServerInstance->Initialize())
  {
    ServerInstance->Create();
    return true;
  }
  else
    return false;
}

bool CAirPlayServer::LoadAnnouncementFromXml(CStdString &srcVers, CStdString &features, CStdString &model, CStdString &mac, CStdString &featuresprotocol)
{
  bool ret = false;
  srcVers.clear();
  features.clear();
  model.clear();
  mac.clear();
  featuresprotocol.clear();

  CStdString airplayFile = CProfilesManager::Get().GetUserDataItem("airplay.xml");
  if (XFILE::CFile::Exists(airplayFile))
  {
    CXBMCTinyXML doc;
    if (!doc.LoadFile(airplayFile))
    {
      CLog::Log(LOGERROR, "%s - Unable to load: %s, Line %d\n%s", 
                __FUNCTION__, airplayFile.c_str(), doc.ErrorRow(), doc.ErrorDesc());
      return ret;
    }
    const TiXmlElement *root = doc.RootElement();
    if (root->ValueStr() != "airplay")
      return ret;
    // read in our passwords
    const TiXmlElement *node = root->FirstChildElement("genericannounce");
    if (node)
    {
      const TiXmlElement *subNode;
      subNode = node->FirstChildElement("mac");
      if (subNode)
        mac = subNode->FirstChild()->Value();
      subNode = node->FirstChildElement("srcvers");
      if (subNode)
        srcVers = subNode->FirstChild()->Value();
      subNode = node->FirstChildElement("model");
      if (subNode)
        model = subNode->FirstChild()->Value();
      subNode = node->FirstChildElement("features");
      if (subNode)
        features = subNode->FirstChild()->Value();
    }
    node = root->FirstChildElement("airplayannounce");
    if (node)
    {
      const TiXmlElement *subNode = node->FirstChildElement("features");
      if (subNode)
        featuresprotocol = subNode->FirstChild()->Value();
    }
  }
  return ret;
}


bool CAirPlayServer::SetCredentials(bool usePassword, const CStdString& password)
{
  bool ret = false;

  if (ServerInstance)
  {
    ret = ServerInstance->SetInternalCredentials(usePassword, password);
  }
  return ret;
}

bool CAirPlayServer::SetInternalCredentials(bool usePassword, const CStdString& password)
{
  m_usePassword = usePassword;
  m_password = password;
  return true;
}

void ClearPhotoAssetCache()
{
  CLog::Log(LOGINFO, "AIRPLAY: Cleaning up photoassetcache");
  // remove all cached photos
  CFileItemList items;
  XFILE::CDirectory::GetDirectory("special://temp/", items);
  
  for (int i = 0; i < items.Size(); ++i)
  {
    CFileItemPtr pItem = items[i];
    if (!pItem->m_bIsFolder)
    {
      if (StringUtils::StartsWithNoCase(pItem->GetLabel(), "airplayasset") &&
          (StringUtils::EndsWithNoCase(pItem->GetLabel(), ".jpg") ||
           StringUtils::EndsWithNoCase(pItem->GetLabel(), ".png") ))
      {
        XFILE::CFile::Delete(pItem->GetPath());
      }
    }
  }  
}

void CAirPlayServer::StopServer(bool bWait)
{
  //clean up the photo cache temp folder
  ClearPhotoAssetCache();

  if (ServerInstance)
  {
    ServerInstance->StopThread(bWait);
    if (bWait)
    {
      delete ServerInstance;
      ServerInstance = NULL;
    }
  }
}

bool CAirPlayServer::IsRunning()
{
  if (ServerInstance == NULL)
    return false;

  return ((CThread*)ServerInstance)->IsRunning();
}

void CAirPlayServer::AnnounceToClients(int state)
{
  CSingleLock lock (m_connectionLock);
  
  std::vector<CTCPClient>::iterator it;
  for (it = m_connections.begin(); it != m_connections.end(); it++)
  {
    CStdString reverseHeader;
    CStdString reverseBody;
    CStdString response;
    int reverseSocket = INVALID_SOCKET;
    it->ComposeReverseEvent(reverseHeader, reverseBody, state);
  
    // Send event status per reverse http socket (play, loading, paused)
    // if we have a reverse header and a reverse socket
    if (reverseHeader.size() > 0 && m_reverseSockets.find(it->m_sessionId) != m_reverseSockets.end())
    {
      //search the reverse socket to this sessionid
      response = StringUtils::Format("POST /event HTTP/1.1\r\n");
      reverseSocket = m_reverseSockets[it->m_sessionId]; //that is our reverse socket
      response += reverseHeader;
    }
    response += "\r\n";
  
    if (reverseBody.size() > 0)
    {
      response += reverseBody;
    }
  
    // don't send it to the connection object
    // the reverse socket itself belongs to
    if (reverseSocket != INVALID_SOCKET && reverseSocket != it->m_socket)
    {
      send(reverseSocket, response.c_str(), response.size(), 0);//send the event status on the eventSocket
    }
  }
}

CAirPlayServer::CAirPlayServer(int port, bool nonlocal) : CThread("AirPlayServer")
{
  m_port = port;
  m_nonlocal = nonlocal;
  m_ServerSocket = INVALID_SOCKET;
  m_usePassword = false;
  m_origVolume = -1;
  CAnnouncementManager::AddAnnouncer(this);
}

CAirPlayServer::~CAirPlayServer()
{
  CAnnouncementManager::RemoveAnnouncer(this);
}

void CAirPlayServer::Process()
{
  m_bStop = false;
  static int sessionCounter = 0;

  while (!m_bStop)
  {
    int             max_fd = 0;
    fd_set          rfds;
    struct timeval  to     = {1, 0};
    FD_ZERO(&rfds);

    FD_SET(m_ServerSocket, &rfds);
    max_fd = m_ServerSocket;

    for (unsigned int i = 0; i < m_connections.size(); i++)
    {
      FD_SET(m_connections[i].m_socket, &rfds);
      if (m_connections[i].m_socket > max_fd)
        max_fd = m_connections[i].m_socket;
    }

    int res = select(max_fd+1, &rfds, NULL, NULL, &to);
    if (res < 0)
    {
      CLog::Log(LOGERROR, "AIRPLAY Server: Select failed");
      Sleep(1000);
      Initialize();
    }
    else if (res > 0)
    {
      for (int i = m_connections.size() - 1; i >= 0; i--)
      {
        int socket = m_connections[i].m_socket;
        if (FD_ISSET(socket, &rfds))
        {
          char buffer[RECEIVEBUFFER] = {};
          int  nread = 0;
          nread = recv(socket, (char*)&buffer, RECEIVEBUFFER, 0);
          if (nread > 0)
          {
            CStdString sessionId;
            m_connections[i].PushBuffer(this, buffer, nread, sessionId, m_reverseSockets);
          }
          if (nread <= 0)
          {
            CSingleLock lock (m_connectionLock);
            CLog::Log(LOGINFO, "AIRPLAY Server: Disconnection detected");
            m_connections[i].Disconnect();
            m_connections.erase(m_connections.begin() + i);
          }
        }
      }

      if (FD_ISSET(m_ServerSocket, &rfds))
      {
        CLog::Log(LOGDEBUG, "AIRPLAY Server: New connection detected");
        CTCPClient newconnection;
        newconnection.m_socket = accept(m_ServerSocket, (struct sockaddr*) &newconnection.m_cliaddr, &newconnection.m_addrlen);
        sessionCounter++;
        newconnection.m_sessionCounter = sessionCounter;

        if (newconnection.m_socket == INVALID_SOCKET)
        {
          CLog::Log(LOGERROR, "AIRPLAY Server: Accept of new connection failed: %d", errno);
          if (EBADF == errno)
          {
            Sleep(1000);
            Initialize();
            break;
          }
        }
        else
        {
          CSingleLock lock (m_connectionLock);
          CLog::Log(LOGINFO, "AIRPLAY Server: New connection added");
          m_connections.push_back(newconnection);
        }
      }
    }
  }

  Deinitialize();
}

bool CAirPlayServer::Initialize()
{
  Deinitialize();
  
  if ((m_ServerSocket = CreateTCPServerSocket(m_port, !m_nonlocal, 10, "AIRPLAY")) == INVALID_SOCKET)
    return false;
  
  CLog::Log(LOGINFO, "AIRPLAY Server: Successfully initialized");
  return true;
}

void CAirPlayServer::Deinitialize()
{
  CSingleLock lock (m_connectionLock);
  for (unsigned int i = 0; i < m_connections.size(); i++)
    m_connections[i].Disconnect();

  m_connections.clear();
  m_reverseSockets.clear();

  if (m_ServerSocket != INVALID_SOCKET)
  {
    shutdown(m_ServerSocket, SHUT_RDWR);
    close(m_ServerSocket);
    m_ServerSocket = INVALID_SOCKET;
  }
}

CAirPlayServer::CTCPClient::CTCPClient()
{
  m_socket = INVALID_SOCKET;
  m_httpParser = new HttpParser();

  m_addrlen = sizeof(struct sockaddr_storage);
  m_pLibPlist = new DllLibPlist();

  m_bAuthenticated = false;
  m_lastEvent = EVENT_NONE;
}

CAirPlayServer::CTCPClient::CTCPClient(const CTCPClient& client)
{
  Copy(client);
  m_httpParser = new HttpParser();
  m_pLibPlist = new DllLibPlist();
}

CAirPlayServer::CTCPClient::~CTCPClient()
{
  if (m_pLibPlist->IsLoaded())
  {
    m_pLibPlist->Unload();
  }
  delete m_pLibPlist;
  delete m_httpParser;
}

CAirPlayServer::CTCPClient& CAirPlayServer::CTCPClient::operator=(const CTCPClient& client)
{
  Copy(client);
  m_httpParser = new HttpParser();
  m_pLibPlist = new DllLibPlist();
  return *this;
}

void CAirPlayServer::CTCPClient::PushBuffer(CAirPlayServer *host, const char *buffer,
                                            int length, CStdString &sessionId, std::map<CStdString,
                                            int> &reverseSockets)
{
  HttpParser::status_t status = m_httpParser->addBytes(buffer, length);

  if (status == HttpParser::Done)
  {
    // Parse the request
    CStdString responseHeader;
    CStdString responseBody;
    int status = ProcessRequest(responseHeader, responseBody);
    sessionId = m_sessionId;
    CStdString statusMsg = "OK";

    switch(status)
    {
      case AIRPLAY_STATUS_NOT_IMPLEMENTED:
        statusMsg = "Not Implemented";
        break;
      case AIRPLAY_STATUS_SWITCHING_PROTOCOLS:
        statusMsg = "Switching Protocols";
        reverseSockets[sessionId] = m_socket;//save this socket as reverse http socket for this sessionid
        break;
      case AIRPLAY_STATUS_NEED_AUTH:
        statusMsg = "Unauthorized";
        break;
      case AIRPLAY_STATUS_NOT_FOUND:
        statusMsg = "Not Found";
        break;
      case AIRPLAY_STATUS_METHOD_NOT_ALLOWED:
        statusMsg = "Method Not Allowed";
        break;
      case AIRPLAY_STATUS_PRECONDITION_FAILED:
        statusMsg = "Precondition Failed";
        break;
    }

    // Prepare the response
    CStdString response;
    const time_t ltime = time(NULL);
    char *date = asctime(gmtime(&ltime)); //Fri, 17 Dec 2010 11:18:01 GMT;
    date[strlen(date) - 1] = '\0'; // remove \n
    response = StringUtils::Format("HTTP/1.1 %d %s\nDate: %s\r\n", status, statusMsg.c_str(), date);
    if (responseHeader.size() > 0)
    {
      response += responseHeader;
    }

    response = StringUtils::Format("%sContent-Length: %d\r\n", response.c_str(), responseBody.size());
    response += "\r\n";

    if (responseBody.size() > 0)
    {
      response += responseBody;
    }

    // Send the response
    //don't send response on AIRPLAY_STATUS_NO_RESPONSE_NEEDED
    if (status != AIRPLAY_STATUS_NO_RESPONSE_NEEDED)
    {
      send(m_socket, response.c_str(), response.size(), 0);
    }
    // We need a new parser...
    delete m_httpParser;
    m_httpParser = new HttpParser;
  }
}

void CAirPlayServer::CTCPClient::Disconnect()
{
  if (m_socket != INVALID_SOCKET)
  {
    CSingleLock lock (m_critSection);
    shutdown(m_socket, SHUT_RDWR);
    close(m_socket);
    m_socket = INVALID_SOCKET;
    delete m_httpParser;
    m_httpParser = NULL;
  }
}

void CAirPlayServer::CTCPClient::Copy(const CTCPClient& client)
{
  m_socket            = client.m_socket;
  m_cliaddr           = client.m_cliaddr;
  m_addrlen           = client.m_addrlen;
  m_httpParser        = client.m_httpParser;
  m_authNonce         = client.m_authNonce;
  m_bAuthenticated    = client.m_bAuthenticated;
  m_sessionCounter    = client.m_sessionCounter;
}


void CAirPlayServer::CTCPClient::ComposeReverseEvent( CStdString& reverseHeader,
                                                      CStdString& reverseBody,
                                                      int state)
{

  if ( m_lastEvent != state )
  { 
    switch(state)
    {
      case EVENT_PLAYING:
      case EVENT_LOADING:
      case EVENT_PAUSED:
      case EVENT_STOPPED:      
        reverseBody = StringUtils::Format(EVENT_INFO, m_sessionCounter, eventStrings[state]);
        CLog::Log(LOGDEBUG, "AIRPLAY: sending event: %s", eventStrings[state]);
        break;
    }
    reverseHeader = "Content-Type: text/x-apple-plist+xml\r\n";
    reverseHeader = StringUtils::Format("%sContent-Length: %d\r\n",reverseHeader.c_str(), reverseBody.size());
    reverseHeader = StringUtils::Format("%sx-apple-session-id: %s\r\n",reverseHeader.c_str(), m_sessionId.c_str());
    m_lastEvent = state;
  }
}

void CAirPlayServer::CTCPClient::ComposeAuthRequestAnswer(CStdString& responseHeader, CStdString& responseBody)
{
  int16_t random=rand();
  CStdString randomStr = StringUtils::Format("%i", random);
  m_authNonce=XBMC::XBMC_MD5::GetMD5(randomStr);
  responseHeader = StringUtils::Format(AUTH_REQUIRED, m_authNonce.c_str());
  responseBody.clear();
}


//as of rfc 2617
CStdString calcResponse(const CStdString& username,
                        const CStdString& password,
                        const CStdString& realm,
                        const CStdString& method,
                        const CStdString& digestUri,
                        const CStdString& nonce)
{
  CStdString response;
  CStdString HA1;
  CStdString HA2;

  HA1 = XBMC::XBMC_MD5::GetMD5(username + ":" + realm + ":" + password);
  HA2 = XBMC::XBMC_MD5::GetMD5(method + ":" + digestUri);
  StringUtils::ToLower(HA1);
  StringUtils::ToLower(HA2);
  response = XBMC::XBMC_MD5::GetMD5(HA1 + ":" + nonce + ":" + HA2);
  StringUtils::ToLower(response);
  return response;
}

//helper function
//from a string field1="value1", field2="value2" it parses the value to a field
CStdString getFieldFromString(const CStdString &str, const char* field)
{
  CStdString tmpStr;
  CStdStringArray tmpAr1;
  CStdStringArray tmpAr2;

  StringUtils::SplitString(str, ",", tmpAr1);

  for(unsigned int i = 0;i<tmpAr1.size();i++)
  {
    if (tmpAr1[i].find(field) != std::string::npos)
    {
      if (StringUtils::SplitString(tmpAr1[i], "=", tmpAr2) == 2)
      {
        StringUtils::Replace(tmpAr2[1], "\"", "");//remove quotes
        return tmpAr2[1];
      }
    }
  }
  return "";
}

bool CAirPlayServer::CTCPClient::checkAuthorization(const CStdString& authStr,
                                                    const CStdString& method,
                                                    const CStdString& uri)
{
  bool authValid = true;

  CStdString username;

  if (authStr.empty())
    return false;

  //first get username - we allow all usernames for airplay (usually it is AirPlay)
  username = getFieldFromString(authStr, "username");
  if (username.empty())
  {
    authValid = false;
  }

  //second check realm
  if (authValid)
  {
    if (getFieldFromString(authStr, "realm") != AUTH_REALM)
    {
      authValid = false;
    }
  }

  //third check nonce
  if (authValid)
  {
    if (getFieldFromString(authStr, "nonce") != m_authNonce)
    {
      authValid = false;
    }
  }

  //forth check uri
  if (authValid)
  {
    if (getFieldFromString(authStr, "uri") != uri)
    {
      authValid = false;
    }
  }

  //last check response
  if (authValid)
  {
     CStdString realm = AUTH_REALM;
     CStdString ourResponse = calcResponse(username, ServerInstance->m_password, realm, method, uri, m_authNonce);
     CStdString theirResponse = getFieldFromString(authStr, "response");
     if (!theirResponse.Equals(ourResponse, false))
     {
       authValid = false;
       CLog::Log(LOGDEBUG,"AirAuth: response mismatch - our: %s theirs: %s",ourResponse.c_str(), theirResponse.c_str());
     }
     else
     {
       CLog::Log(LOGDEBUG, "AirAuth: successfull authentication from AirPlay client");
     }
  }
  m_bAuthenticated = authValid;
  return m_bAuthenticated;
}

void CAirPlayServer::backupVolume()
{
  if (ServerInstance->m_origVolume == -1)
    ServerInstance->m_origVolume = (int)g_application.GetVolume();
}

void CAirPlayServer::restoreVolume()
{
  if (ServerInstance->m_origVolume != -1 && CSettings::Get().GetBool("services.airplayvolumecontrol"))
  {
    g_application.SetVolume((float)ServerInstance->m_origVolume);
    ServerInstance->m_origVolume = -1;
  }
}

void dumpPlist(DllLibPlist *pLibPlist, plist_t *dict)
{
  char *plist = NULL;
  uint32_t len = 0;
  pLibPlist->plist_to_xml(dict,&plist, &len);
  CLog::Log(LOGDEBUG, "%s", plist);
  
}

std::string getStringFromPlist(DllLibPlist *pLibPlist,plist_t node)
{
  std::string ret;
  char *tmpStr = NULL;
  pLibPlist->plist_get_string_val(node, &tmpStr);
  ret = tmpStr;
#ifdef TARGET_WINDOWS
  pLibPlist->plist_free_string_val(tmpStr);
#else
  free(tmpStr);
#endif
  return ret;
}

int CAirPlayServer::CTCPClient::ProcessRequest( CStdString& responseHeader,
                                                CStdString& responseBody)
{
  CStdString method = m_httpParser->getMethod();
  CStdString uri = m_httpParser->getUri();
  CStdString queryString = m_httpParser->getQueryString();
  CStdString body = m_httpParser->getBody();
  CStdString contentType = m_httpParser->getValue("content-type");
  m_sessionId = m_httpParser->getValue("x-apple-session-id");
  CStdString authorization = m_httpParser->getValue("authorization");
  CStdString photoAction = m_httpParser->getValue("x-apple-assetaction");
  CStdString photoCacheId = m_httpParser->getValue("x-apple-assetkey");
  int status = AIRPLAY_STATUS_OK;
  bool needAuth = false;
  
  if (m_sessionId.empty())
    m_sessionId = "00000000-0000-0000-0000-000000000000";

  if (ServerInstance->m_usePassword && !m_bAuthenticated)
  {
    needAuth = true;
  }

  size_t startQs = uri.find('?');
  if (startQs != std::string::npos)
  {
    uri.erase(startQs);
  }

  // This is the socket which will be used for reverse HTTP
  // negotiate reverse HTTP via upgrade
  if (uri == "/reverse")
  {
    status = AIRPLAY_STATUS_SWITCHING_PROTOCOLS;
    responseHeader = "Upgrade: PTTH/1.0\r\nConnection: Upgrade\r\n";
  }

  // The rate command is used to play/pause media.
  // A value argument should be supplied which indicates media should be played or paused.
  // 0.000000 => pause
  // 1.000000 => play
  else if (uri == "/rate")
  {
      const char* found = strstr(queryString.c_str(), "value=");
      int rate = found ? (int)(atof(found + strlen("value=")) + 0.5f) : 0;

      CLog::Log(LOGDEBUG, "AIRPLAY: got request %s with rate %i", uri.c_str(), rate);

      if (needAuth && !checkAuthorization(authorization, method, uri))
      {
        status = AIRPLAY_STATUS_NEED_AUTH;
      }
      else if (rate == 0)
      {
        if (g_application.m_pPlayer->IsPlaying() && !g_application.m_pPlayer->IsPaused())
        {
          CApplicationMessenger::Get().MediaPause();
        }
      }
      else
      {
        if (g_application.m_pPlayer->IsPausedPlayback())
        {
          CApplicationMessenger::Get().MediaPause();
        }
      }
  }
  
  // The volume command is used to change playback volume.
  // A value argument should be supplied which indicates how loud we should get.
  // 0.000000 => silent
  // 1.000000 => loud
  else if (uri == "/volume")
  {
      const char* found = strstr(queryString.c_str(), "volume=");
      float volume = found ? (float)strtod(found + strlen("volume="), NULL) : 0;

      CLog::Log(LOGDEBUG, "AIRPLAY: got request %s with volume %f", uri.c_str(), volume);

      if (needAuth && !checkAuthorization(authorization, method, uri))
      {
        status = AIRPLAY_STATUS_NEED_AUTH;
      }
      else if (volume >= 0 && volume <= 1)
      {
        float oldVolume = g_application.GetVolume();
        volume *= 100;
        if(oldVolume != volume && CSettings::Get().GetBool("services.airplayvolumecontrol"))
        {
          backupVolume();
          g_application.SetVolume(volume);          
          CApplicationMessenger::Get().ShowVolumeBar(oldVolume < volume);
        }
      }
  }


  // Contains a header like format in the request body which should contain a
  // Content-Location and optionally a Start-Position
  else if (uri == "/play")
  {
    CStdString location;
    float position = 0.0;
    m_lastEvent = EVENT_NONE;

    CLog::Log(LOGDEBUG, "AIRPLAY: got request %s", uri.c_str());

    if (needAuth && !checkAuthorization(authorization, method, uri))
    {
      status = AIRPLAY_STATUS_NEED_AUTH;
    }
    else if (contentType == "application/x-apple-binary-plist")
    {
      CAirPlayServer::m_isPlaying++;    
      
      if (m_pLibPlist->Load())
      {
        m_pLibPlist->EnableDelayedUnload(false);

        const char* bodyChr = m_httpParser->getBody();

        plist_t dict = NULL;
        m_pLibPlist->plist_from_bin(bodyChr, m_httpParser->getContentLength(), &dict);

        if (m_pLibPlist->plist_dict_get_size(dict))
        {
          plist_t tmpNode = m_pLibPlist->plist_dict_get_item(dict, "Start-Position");
          if (tmpNode)
          {
            double tmpDouble = 0;
            m_pLibPlist->plist_get_real_val(tmpNode, &tmpDouble);
            position = (float)tmpDouble;
          }

          tmpNode = m_pLibPlist->plist_dict_get_item(dict, "Content-Location");
          if (tmpNode)
          {
            location = getStringFromPlist(m_pLibPlist, tmpNode);
            tmpNode = NULL;
          }
          
          // in newer protocol versions the location is given
          // via host and path where host is ip:port and path is /path/file.mov
          if (location.empty())
              tmpNode = m_pLibPlist->plist_dict_get_item(dict, "host");
          if (tmpNode)
          {
            location = "http://";
            location += getStringFromPlist(m_pLibPlist, tmpNode);

            tmpNode = m_pLibPlist->plist_dict_get_item(dict, "path");
            if (tmpNode)
            {
              location += getStringFromPlist(m_pLibPlist, tmpNode);
            }
          }

          if (dict)
          {
            m_pLibPlist->plist_free(dict);
          }
        }
        else
        {
          CLog::Log(LOGERROR, "Error parsing plist");
        }
        m_pLibPlist->Unload();
      }
    }
    else
    {
      CAirPlayServer::m_isPlaying++;        
      // Get URL to play
      std::string contentLocation = "Content-Location: ";
      size_t start = body.find(contentLocation);
      if (start == std::string::npos)
        return AIRPLAY_STATUS_NOT_IMPLEMENTED;
      start += contentLocation.size();
      int end = body.find('\n', start);
      location = body.substr(start, end - start);

      std::string startPosition = "Start-Position: ";
      start = body.find(startPosition);
      if (start != std::string::npos)
      {
        start += startPosition.size();
        int end = body.find('\n', start);
        std::string positionStr = body.substr(start, end - start);
        position = (float)atof(positionStr.c_str());
      }
    }

    if (status != AIRPLAY_STATUS_NEED_AUTH)
    {
      CStdString userAgent="AppleCoreMedia/1.0.0.8F455 (AppleTV; U; CPU OS 4_3 like Mac OS X; de_de)";
      CURL::Encode(userAgent);
      location += "|User-Agent=" + userAgent;

      CFileItem fileToPlay(location, false);
      fileToPlay.SetProperty("StartPercent", position*100.0f);
      ServerInstance->AnnounceToClients(EVENT_LOADING);
      // froce to internal dvdplayer cause it is the only
      // one who will work well with airplay
      g_application.m_eForcedNextPlayer = EPC_DVDPLAYER;
      CApplicationMessenger::Get().MediaPlay(fileToPlay);
    }
  }
  
  // seems to be new with higher protocol versions
  // is used by youtube app to tell us to remove a playlist/item
  // known actions so far are
  // "type - playlistRemove"
  // "params - dict with items - with dict with uuid
  else if (uri == "/action")
  {
    CLog::Log(LOGDEBUG, "AIRPLAY: got request %s", uri.c_str());
    
    if (needAuth && !checkAuthorization(authorization, method, uri))
    {
      status = AIRPLAY_STATUS_NEED_AUTH;
    }
    else if (contentType == "application/x-apple-binary-plist")
    {     
      if (m_pLibPlist->Load())
      {
        m_pLibPlist->EnableDelayedUnload(false);
        
        const char* bodyChr = m_httpParser->getBody();
        
        plist_t dict = NULL;
        m_pLibPlist->plist_from_bin(bodyChr, m_httpParser->getContentLength(), &dict);
        
        if (m_pLibPlist->plist_dict_get_size(dict))
        {          
          plist_t tmpNode = m_pLibPlist->plist_dict_get_item(dict, "type");
          if (tmpNode)
          {
            std::string tmpStr = getStringFromPlist(m_pLibPlist, tmpNode);
            if (StringUtils::CompareNoCase(tmpStr, "playlistRemove") == 0)
            {
              if (IsPlaying()) //only stop player if we started him
              {
                CApplicationMessenger::Get().MediaStop();
                CAirPlayServer::m_isPlaying--;
              }
            }
          }
        }
      }
    }
  }

  // Used to perform seeking (POST request) and to retrieve current player position (GET request).
  // GET scrub seems to also set rate 1 - strange but true
  else if (uri == "/scrub")
  {
    if (needAuth && !checkAuthorization(authorization, method, uri))
    {
      status = AIRPLAY_STATUS_NEED_AUTH;
    }
    else if (method == "GET")
    {
      CLog::Log(LOGDEBUG, "AIRPLAY: got GET request %s", uri.c_str());
      
      if (g_application.m_pPlayer->GetTotalTime())
      {
        float position = ((float) g_application.m_pPlayer->GetTime()) / 1000;
        responseBody = StringUtils::Format("duration: %.6f\r\nposition: %.6f\r\n", (float)g_application.m_pPlayer->GetTotalTime() / 1000, position);
      }
      else 
      {
        status = AIRPLAY_STATUS_METHOD_NOT_ALLOWED;
      }
    }
    else
    {
      const char* found = strstr(queryString.c_str(), "position=");
      
      if (found && g_application.m_pPlayer->HasPlayer())
      {
        int64_t position = (int64_t) (atof(found + strlen("position=")) * 1000.0);
        g_application.m_pPlayer->SeekTime(position);
        CLog::Log(LOGDEBUG, "AIRPLAY: got POST request %s with pos %"PRId64, uri.c_str(), position);
      }
    }
  }

  // Sent when media playback should be stopped
  else if (uri == "/stop")
  {
    CLog::Log(LOGDEBUG, "AIRPLAY: got request %s", uri.c_str());
    if (needAuth && !checkAuthorization(authorization, method, uri))
    {
      status = AIRPLAY_STATUS_NEED_AUTH;
    }
    else
    {
      if (IsPlaying()) //only stop player if we started him
      {
        CApplicationMessenger::Get().MediaStop();
        CAirPlayServer::m_isPlaying--;
      }
      else //if we are not playing and get the stop request - we just wanna stop picture streaming
      {
        CApplicationMessenger::Get().SendAction(ACTION_PREVIOUS_MENU);
      }
    }
    ClearPhotoAssetCache();
  }

  // RAW JPEG data is contained in the request body
  else if (uri == "/photo")
  {
    CLog::Log(LOGDEBUG, "AIRPLAY: got request %s", uri.c_str());
    if (needAuth && !checkAuthorization(authorization, method, uri))
    {
      status = AIRPLAY_STATUS_NEED_AUTH;
    }
    else if (m_httpParser->getContentLength() > 0 || photoAction == "displayCached")
    {
      XFILE::CFile tmpFile;
      CStdString tmpFileName = "special://temp/airplayasset";
      bool showPhoto = true;
      bool receivePhoto = true;

      
      if (photoAction == "cacheOnly")
        showPhoto = false;
      else if (photoAction == "displayCached")
      {
        receivePhoto = false;
        if (photoCacheId.length())
          CLog::Log(LOGDEBUG, "AIRPLAY: Trying to show from cache asset: %s", photoCacheId.c_str());
      }
      
      if (photoCacheId.length())
        tmpFileName += photoCacheId;
      else
        tmpFileName += "airplay_photo";
             
      if( receivePhoto && m_httpParser->getContentLength() > 3 &&
          m_httpParser->getBody()[1] == 'P' &&
          m_httpParser->getBody()[2] == 'N' &&
          m_httpParser->getBody()[3] == 'G')
      {
        tmpFileName += ".png";
      }
      else
      {
        tmpFileName += ".jpg";
      }

      int writtenBytes=0;
      if (receivePhoto)
      {
        if (tmpFile.OpenForWrite(tmpFileName, true))
        {
          writtenBytes = tmpFile.Write(m_httpParser->getBody(), m_httpParser->getContentLength());
          tmpFile.Close();
        }
        if (photoCacheId.length())
          CLog::Log(LOGDEBUG, "AIRPLAY: Cached asset: %s", photoCacheId.c_str());
      }

      if (showPhoto)
      {
        if ((writtenBytes > 0 && (unsigned int)writtenBytes == m_httpParser->getContentLength()) || !receivePhoto)
        {
          if (!receivePhoto && !XFILE::CFile::Exists(tmpFileName))
          {
            status = AIRPLAY_STATUS_PRECONDITION_FAILED; //image not found in the cache
            if (photoCacheId.length())
              CLog::Log(LOGWARNING, "AIRPLAY: Asset %s not found in our cache.", photoCacheId.c_str());
          }
          else
            CApplicationMessenger::Get().PictureShow(tmpFileName);
        }
        else
        {
          CLog::Log(LOGERROR,"AirPlayServer: Error writing tmpFile.");
        }
      }
    }
  }

  else if (uri == "/playback-info")
  {
    float position = 0.0f;
    float duration = 0.0f;
    float cachePosition = 0.0f;
    bool playing = false;

    CLog::Log(LOGDEBUG, "AIRPLAY: got request %s", uri.c_str());

    if (needAuth && !checkAuthorization(authorization, method, uri))
    {
      status = AIRPLAY_STATUS_NEED_AUTH;
    }
    else if (g_application.m_pPlayer->HasPlayer())
    {
      if (g_application.m_pPlayer->GetTotalTime())
      {
        position = ((float) g_application.m_pPlayer->GetTime()) / 1000;
        duration = ((float) g_application.m_pPlayer->GetTotalTime()) / 1000;
        playing = !g_application.m_pPlayer->IsPaused();
        cachePosition = position + (duration * g_application.m_pPlayer->GetCachePercentage() / 100.0f);
      }

      responseBody = StringUtils::Format(PLAYBACK_INFO, duration, cachePosition, position, (playing ? 1 : 0), duration);
      responseHeader = "Content-Type: text/x-apple-plist+xml\r\n";

      if (g_application.m_pPlayer->IsCaching())
      {
        CAirPlayServer::ServerInstance->AnnounceToClients(EVENT_LOADING);
      }
    }
    else
    {
      responseBody = StringUtils::Format(PLAYBACK_INFO_NOT_READY, duration, cachePosition, position, (playing ? 1 : 0), duration);
      responseHeader = "Content-Type: text/x-apple-plist+xml\r\n";     
    }
  }

  else if (uri == "/server-info")
  {
    CLog::Log(LOGDEBUG, "AIRPLAY: got request %s", uri.c_str());
    responseBody = StringUtils::Format(SERVER_INFO, macAdr.c_str(), featuresProtocol.c_str(), srvname.c_str(), srvvers.c_str());
    responseHeader = "Content-Type: text/x-apple-plist+xml\r\n";
  }

  else if (uri == "/slideshow-features")
  {
    // Ignore for now.
  }

  else if (uri == "/authorize")
  {
    // DRM, ignore for now.
  }
  
  else if (uri == "/setProperty")
  {
    status = AIRPLAY_STATUS_NOT_FOUND;
  }

  else if (uri == "/getProperty")
  {
    status = AIRPLAY_STATUS_NOT_FOUND;
  }

  else if (uri == "/fp-setup")
  {
    status = AIRPLAY_STATUS_PRECONDITION_FAILED;
  }  

  else if (uri == "200") //response OK from the event reverse message
  {
    status = AIRPLAY_STATUS_NO_RESPONSE_NEEDED;
  }
  else
  {
    CLog::Log(LOGERROR, "AIRPLAY Server: unhandled request [%s]\n", uri.c_str());
    status = AIRPLAY_STATUS_NOT_IMPLEMENTED;
  }

  if (status == AIRPLAY_STATUS_NEED_AUTH)
  {
    ComposeAuthRequestAnswer(responseHeader, responseBody);
  }

  return status;
}

#endif
