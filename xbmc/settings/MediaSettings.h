/*
 *  Copyright (C) 2013-2018 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#pragma once

#include "cores/VideoSettings.h"
#include "settings/GameSettings.h"
#include "settings/ISubSettings.h"
#include "settings/LibExportSettings.h"
#include "settings/lib/ISettingCallback.h"
#include "settings/lib/ISettingsHandler.h"
#include "threads/CriticalSection.h"

#include <map>
#include <string>

constexpr int VOLUME_DRC_MINIMUM = 0; // 0dB
constexpr int VOLUME_DRC_MAXIMUM = 6000; // 60dB

class TiXmlNode;

enum WatchedMode
{
  WatchedModeAll = 0,
  WatchedModeUnwatched,
  WatchedModeWatched
};

class CMediaSettings : public ISettingCallback, public ISettingsHandler, public ISubSettings
{
public:
  static CMediaSettings& GetInstance();

  bool Load(const TiXmlNode *settings) override;
  bool Save(TiXmlNode *settings) const override;

  void OnSettingAction(const std::shared_ptr<const CSetting>& setting) override;
  void OnSettingChanged(const std::shared_ptr<const CSetting>& setting) override;

  const CVideoSettings& GetDefaultVideoSettings() const { return m_defaultVideoSettings; }
  CVideoSettings& GetDefaultVideoSettings() { return m_defaultVideoSettings; }

  const CGameSettings& GetDefaultGameSettings() const { return m_defaultGameSettings; }
  CGameSettings& GetDefaultGameSettings() { return m_defaultGameSettings; }
  const CGameSettings& GetCurrentGameSettings() const { return m_currentGameSettings; }
  CGameSettings& GetCurrentGameSettings() { return m_currentGameSettings; }

  /*! \brief Retrieve the watched mode for the given content type
   \param content Current content type
   \return the current watch mode for this content type, WATCH_MODE_ALL if the content type is unknown.
   \sa SetWatchMode
   */
  int GetWatchedMode(const std::string &content) const;

  /*! \brief Set the watched mode for the given content type
   \param content Current content type
   \param value Watched mode to set
   \sa GetWatchMode
   */
  void SetWatchedMode(const std::string &content, WatchedMode mode);

  /*! \brief Cycle the watched mode for the given content type
   \param content Current content type
   \sa GetWatchMode, SetWatchMode
   */
  void CycleWatchedMode(const std::string &content);

  void SetMusicPlaylistRepeat(bool repeats) { m_musicPlaylistRepeat = repeats; }
  void SetMusicPlaylistShuffled(bool shuffled) { m_musicPlaylistShuffle = shuffled; }

  void SetVideoPlaylistRepeat(bool repeats) { m_videoPlaylistRepeat = repeats; }
  void SetVideoPlaylistShuffled(bool shuffled) { m_videoPlaylistShuffle = shuffled; }

  bool DoesMediaStartWindowed() const { return m_mediaStartWindowed; }
  void SetMediaStartWindowed(bool windowed) { m_mediaStartWindowed = windowed; }
  int GetAdditionalSubtitleDirectoryChecked() const { return m_additionalSubtitleDirectoryChecked; }
  void SetAdditionalSubtitleDirectoryChecked(int checked) { m_additionalSubtitleDirectoryChecked = checked; }

  int GetMusicNeedsUpdate() const { return m_musicNeedsUpdate; }
  void SetMusicNeedsUpdate(int version) { m_musicNeedsUpdate = version; }
  int GetVideoNeedsUpdate() const { return m_videoNeedsUpdate; }
  void SetVideoNeedsUpdate(int version) { m_videoNeedsUpdate = version; }

protected:
  CMediaSettings() = default;
  CMediaSettings(const CMediaSettings&) = delete;
  CMediaSettings& operator=(CMediaSettings const&) = delete;
  ~CMediaSettings() override = default;

  static std::string GetWatchedContent(const std::string &content);

private:
  CVideoSettings m_defaultVideoSettings;

  CGameSettings m_defaultGameSettings;
  CGameSettings m_currentGameSettings;

  using WatchedModes = std::map<std::string, WatchedMode, std::less<>>;
  WatchedModes m_watchedModes{{"files", WatchedModeAll},
                              {"movies", WatchedModeAll},
                              {"tvshows", WatchedModeAll},
                              {"musicvideos", WatchedModeAll},
                              {"recordings", WatchedModeAll}};

  bool m_musicPlaylistRepeat{false};
  bool m_musicPlaylistShuffle{false};
  bool m_videoPlaylistRepeat{false};
  bool m_videoPlaylistShuffle{false};

  bool m_mediaStartWindowed{false};
  int m_additionalSubtitleDirectoryChecked{0};

  int m_musicNeedsUpdate{
      0}; ///< if a database update means an update is required (set to the version number of the db)
  int m_videoNeedsUpdate{
      0}; ///< if a database update means an update is required (set to the version number of the db)

  mutable CCriticalSection m_critical;
};
