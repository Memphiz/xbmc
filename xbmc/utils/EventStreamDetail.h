/*
 *  Copyright (C) 2016-2018 Team Kodi
 *  This file is part of Kodi - https://kodi.tv
 *
 *  SPDX-License-Identifier: GPL-2.0-or-later
 *  See LICENSES/README.md for more information.
 */

#pragma once

#include "threads/CriticalSection.h"

#include <functional>
#include <mutex>

namespace detail
{

template<typename Event>
class ISubscription
{
public:
  virtual void HandleEvent(const Event& event) = 0;
  virtual void Cancel() = 0;
  virtual bool IsOwnedBy(void* obj) = 0;
  virtual ~ISubscription() = default;
};

template<typename Event, typename Owner>
class CSubscription : public ISubscription<Event>
{
public:
  using EventHandler = std::function<void(const Event&)>;
  CSubscription(Owner* owner, const EventHandler& eventHandler);
  void HandleEvent(const Event& event) override;
  void Cancel() override;
  bool IsOwnedBy(void *obj) override;

private:
  Owner* m_owner;
  EventHandler m_eventHandler;
  CCriticalSection m_criticalSection;
};

template<typename Event, typename Owner>
CSubscription<Event, Owner>::CSubscription(Owner* owner, const EventHandler& eventHandler)
  : m_owner(owner), m_eventHandler(eventHandler)
{}

template<typename Event, typename Owner>
bool CSubscription<Event, Owner>::IsOwnedBy(void* obj)
{
  std::unique_lock lock(m_criticalSection);
  return obj != nullptr && obj == m_owner;
}

template<typename Event, typename Owner>
void CSubscription<Event, Owner>::Cancel()
{
  std::unique_lock lock(m_criticalSection);
  m_owner = nullptr;
}

template<typename Event, typename Owner>
void CSubscription<Event, Owner>::HandleEvent(const Event& event)
{
  std::unique_lock lock(m_criticalSection);
  if (m_owner)
    m_eventHandler(event);
}
}
