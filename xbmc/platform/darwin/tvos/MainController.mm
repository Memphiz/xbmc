/*
 *      Copyright (C) 2010-2013 Team XBMC
 *      http://xbmc.org
 *
 *  This Program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
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
 *
 *  Refactored. Copyright (C) 2015 Team MrMC
 *  https://github.com/MrMC
 *
 */

#import "system.h"

#define BOOL XBMC_BOOL
#include "Application.h"
#include "FileItem.h"
#include "MusicInfoTag.h"
#include "SpecialProtocol.h"
#include "PlayList.h"

#define id _id
#include "TextureCache.h"
#undef id

#include "guilib/GUIWindowManager.h"
#include "input/Key.h"
#include "input/touch/generic/GenericTouchActionHandler.h"
#include "messaging/ApplicationMessenger.h"

#include "platform/darwin/AutoPool.h"
#include "platform/darwin/DarwinUtils.h"
#include "platform/darwin/NSLogDebugHelpers.h"
#include "platform/darwin/tvos/MainEAGLView.h"
#include "platform/darwin/tvos/MainController.h"
#include "platform/darwin/tvos/MainApplication.h"
#include "platform/xbmc.h"
#include "platform/XbmcContext.h"
#include "settings/AdvancedSettings.h"
#include "utils/Variant.h"
#include "windowing/WindowingFactory.h"

#undef BOOL

#import <MediaPlayer/MPMediaItem.h>
#import <MediaPlayer/MPNowPlayingInfoCenter.h>

using namespace KODI::MESSAGING;

MainController *g_xbmcController;

// notification messages
extern NSString* kBRScreenSaverActivated;
extern NSString* kBRScreenSaverDismissed;

id objectFromVariant(const CVariant &data);

NSArray *arrayFromVariantArray(const CVariant &data)
{
  if (!data.isArray())
    return nil;
  NSMutableArray *array = [[[NSMutableArray alloc] initWithCapacity:data.size()] autorelease];
  for (CVariant::const_iterator_array itr = data.begin_array(); itr != data.end_array(); ++itr)
    [array addObject:objectFromVariant(*itr)];

  return array;
}

NSDictionary *dictionaryFromVariantMap(const CVariant &data)
{
  if (!data.isObject())
    return nil;
  NSMutableDictionary *dict = [[[NSMutableDictionary alloc] initWithCapacity:data.size()] autorelease];
  for (CVariant::const_iterator_map itr = data.begin_map(); itr != data.end_map(); ++itr)
    [dict setValue:objectFromVariant(itr->second) forKey:[NSString stringWithUTF8String:itr->first.c_str()]];

  return dict;
}

id objectFromVariant(const CVariant &data)
{
  if (data.isNull())
    return nil;
  if (data.isString())
    return [NSString stringWithUTF8String:data.asString().c_str()];
  if (data.isWideString())
    return [NSString stringWithCString:(const char *)data.asWideString().c_str() encoding:NSUnicodeStringEncoding];
  if (data.isInteger())
    return [NSNumber numberWithLongLong:data.asInteger()];
  if (data.isUnsignedInteger())
    return [NSNumber numberWithUnsignedLongLong:data.asUnsignedInteger()];
  if (data.isBoolean())
    return [NSNumber numberWithInt:data.asBoolean()?1:0];
  if (data.isDouble())
    return [NSNumber numberWithDouble:data.asDouble()];
  if (data.isArray())
    return arrayFromVariantArray(data);
  if (data.isObject())
    return dictionaryFromVariantMap(data);

  return nil;
}

//--------------------------------------------------------------
//

#pragma mark - MainController interface
@interface MainController ()
@property (strong, nonatomic) NSTimer *pressAutoRepeatTimer;

@end

#pragma mark - MainController implementation
@implementation MainController

@synthesize m_lastGesturePoint;
@synthesize m_screenScale;
@synthesize m_touchBeginSignaled;
@synthesize m_touchDirection;
@synthesize m_currentKey;
@synthesize m_screenIdx;
@synthesize m_currentClick;
@synthesize m_screensize;
@synthesize m_clickResetPan;

// set to 1 to enable new remote function, to be tested for 1.0.2
#define NEW_REMOTE_HANDLING 0

#pragma mark - internal key press methods
//--------------------------------------------------------------
//--------------------------------------------------------------
- (void)sendKeyDownUp:(XBMCKey)key
{
  XBMC_Event newEvent = {0};
  newEvent.key.keysym.sym = key;

  newEvent.type = XBMC_KEYDOWN;
  CWinEvents::MessagePush(&newEvent);

  newEvent.type = XBMC_KEYUP;
  CWinEvents::MessagePush(&newEvent);
}
- (void)sendKeyDown:(XBMCKey)key
{
  XBMC_Event newEvent = {0};
  newEvent.type = XBMC_KEYDOWN;
  newEvent.key.keysym.sym = key;
  CWinEvents::MessagePush(&newEvent);
}
- (void)sendKeyUp:(XBMCKey)key
{
  XBMC_Event newEvent = {0};
  newEvent.type = XBMC_KEYUP;
  newEvent.key.keysym.sym = key;
  CWinEvents::MessagePush(&newEvent);
}

#pragma mark - key press auto-repeat methods
//--------------------------------------------------------------
//--------------------------------------------------------------
// start repeating after 0.25s
#define REPEATED_KEYPRESS_DELAY_S 0.50
// pause 0.05s (50ms) between keypresses
#define REPEATED_KEYPRESS_PAUSE_S 0.05
//--------------------------------------------------------------

- (void)startKeyPressTimer:(XBMCKey)keyId
{
  [self startKeyPressTimer:keyId clickTime:REPEATED_KEYPRESS_PAUSE_S];
}

- (void)startKeyPressTimer:(XBMCKey)keyId clickTime:(NSTimeInterval)interval
{
  //PRINT_SIGNATURE();
  if (self.pressAutoRepeatTimer != nil)
    [self stopKeyPressTimer];

  [self sendKeyDown:keyId];

  NSNumber *number = [NSNumber numberWithInt:keyId];
  NSDate *fireDate = [NSDate dateWithTimeIntervalSinceNow:REPEATED_KEYPRESS_DELAY_S];

  // schedule repeated timer which starts after REPEATED_KEYPRESS_DELAY_S
  // and fires every REPEATED_KEYPRESS_PAUSE_S
  NSTimer *timer = [[NSTimer alloc] initWithFireDate:fireDate
    interval:interval
    target:self
    selector:@selector(keyPressTimerCallback:)
    userInfo:number
    repeats:YES];

  // schedule the timer to the runloop
  [[NSRunLoop currentRunLoop] addTimer:timer forMode:NSDefaultRunLoopMode];
  self.pressAutoRepeatTimer = timer;
}
- (void)stopKeyPressTimer
{
  //PRINT_SIGNATURE();
  if (self.pressAutoRepeatTimer != nil)
  {
    [self.pressAutoRepeatTimer invalidate];
    [self.pressAutoRepeatTimer release];
    self.pressAutoRepeatTimer = nil;
  }
}
- (void)keyPressTimerCallback:(NSTimer*)theTimer
{
  //PRINT_SIGNATURE();
  // if queue is empty - skip this timer event before letting it process
  if (CWinEvents::GetQueueSize())
    return;

  NSNumber *keyId = [theTimer userInfo];
  [self sendKeyDown:(XBMCKey)[keyId intValue]];
}

- (XBMCKey)getPanDirection:(CGPoint)translation
{
  int x = (int)translation.x;
  int y = (int)translation.y;
  int absX = x;
  int absY = y;
  
  if (absX < 0)
    absX *= -1;
  
  if (absY < 0)
    absY *= -1;
  
  bool horizontal, veritical;
  horizontal = ( absX > absY ) ;
  veritical = !horizontal;
  
  // Determine up, down, right, or left:
  bool swipe_up, swipe_down, swipe_left, swipe_right;
  swipe_left = (horizontal && x < 0);
  swipe_right = (horizontal && x >= 0);
  swipe_up = (veritical && y < 0);
  swipe_down = (veritical && y >= 0);
  
  if (swipe_down)
    return XBMCK_DOWN;
  if (swipe_up)
    return XBMCK_UP;
  if (swipe_left)
    return XBMCK_LEFT;
  if (swipe_right)
    return XBMCK_RIGHT;
  
  return XBMCK_UNKNOWN;
}

//--------------------------------------------------------------
//--------------------------------------------------------------
#pragma mark - gesture methods
//--------------------------------------------------------------
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldReceiveTouch:(UITouch *)touch
{
  //PRINT_SIGNATURE();
  return YES;
}

//--------------------------------------------------------------
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldRecognizeSimultaneouslyWithGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer
{  
  if ([gestureRecognizer isKindOfClass:[UISwipeGestureRecognizer class]] && [otherGestureRecognizer isKindOfClass:[UIPanGestureRecognizer class]]) {
    return YES;
  }
  if ([gestureRecognizer isKindOfClass:[UIPanGestureRecognizer class]] && [otherGestureRecognizer isKindOfClass:[UILongPressGestureRecognizer class]]) {
    return YES;
  }
  if ([gestureRecognizer isKindOfClass:[UITapGestureRecognizer class]] && [otherGestureRecognizer isKindOfClass:[UIPanGestureRecognizer class]]) {
    return YES;
  }
  return NO;
}

- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldRequireFailureOfGestureRecognizer:(UIGestureRecognizer *)otherGestureRecognizer
{
// enable for new remote function
#if (NEW_REMOTE_HANDLING)
  if ([gestureRecognizer isKindOfClass:[UIPanGestureRecognizer class]] && ([otherGestureRecognizer isKindOfClass:[UISwipeGestureRecognizer class]] || [otherGestureRecognizer isKindOfClass:[UITapGestureRecognizer class]]))
  {
    return YES;
  }
#endif
  return NO;
}

//--------------------------------------------------------------
// called before pressesBegan:withEvent: is called on the gesture recognizer
// for a new press. return NO to prevent the gesture recognizer from seeing this press
- (BOOL)gestureRecognizer:(UIGestureRecognizer *)gestureRecognizer shouldReceivePress:(UIPress *)press
{
  //PRINT_SIGNATURE();
  BOOL handled = YES;
  switch (press.type)
  {
    // single press key, but also detect hold and back to tvos.
    case UIPressTypeMenu:
      // menu is special.
      //  a) if at our home view, should return to atv home screen.
      //  b) if not, let it pass to us.
      if (g_windowManager.GetActiveWindow() == WINDOW_HOME && g_windowManager.GetFocusedWindow() != WINDOW_DIALOG_FAVOURITES)
        handled = NO;
      break;

    // single press keys
    case UIPressTypeSelect:
    case UIPressTypePlayPause:
      break;

    // auto-repeat keys
    case UIPressTypeUpArrow:
    case UIPressTypeDownArrow:
    case UIPressTypeLeftArrow:
    case UIPressTypeRightArrow:
      break;

    default:
      return NO;
  }

  return handled;
}

//--------------------------------------------------------------
- (void)createSwipeGestureRecognizers
{
  UISwipeGestureRecognizer *swipeLeft = [[UISwipeGestureRecognizer alloc]
                                         initWithTarget:self action:@selector(handleSwipe:)];

  swipeLeft.delaysTouchesBegan = NO;
  swipeLeft.direction = UISwipeGestureRecognizerDirectionLeft;
  swipeLeft.delegate = self;
  [m_glView addGestureRecognizer:swipeLeft];
  [swipeLeft release];

  //single finger swipe right
  UISwipeGestureRecognizer *swipeRight = [[UISwipeGestureRecognizer alloc]
                                          initWithTarget:self action:@selector(handleSwipe:)];

  swipeRight.delaysTouchesBegan = NO;
  swipeRight.direction = UISwipeGestureRecognizerDirectionRight;
  swipeRight.delegate = self;
  [m_glView addGestureRecognizer:swipeRight];
  [swipeRight release];

  //single finger swipe up
  UISwipeGestureRecognizer *swipeUp = [[UISwipeGestureRecognizer alloc]
                                       initWithTarget:self action:@selector(handleSwipe:)];

  swipeUp.delaysTouchesBegan = NO;
  swipeUp.direction = UISwipeGestureRecognizerDirectionUp;
  swipeUp.delegate = self;
  [m_glView addGestureRecognizer:swipeUp];
  [swipeUp release];

  //single finger swipe down
  UISwipeGestureRecognizer *swipeDown = [[UISwipeGestureRecognizer alloc]
                                         initWithTarget:self action:@selector(handleSwipe:)];

  swipeDown.delaysTouchesBegan = NO;
  swipeDown.direction = UISwipeGestureRecognizerDirectionDown;
  swipeDown.delegate = self;
  [m_glView addGestureRecognizer:swipeDown];
  [swipeDown release];
}
  
//--------------------------------------------------------------
- (void)createPanGestureRecognizers
{
  //PRINT_SIGNATURE();
  // for pan gestures with one finger
  auto pan = [[UIPanGestureRecognizer alloc]
    initWithTarget:self action:@selector(handlePan:)];
  pan.delegate = self;
  [m_glView addGestureRecognizer:pan];
  [pan release];
  m_clickResetPan = false;
}
//--------------------------------------------------------------
- (void)createTapGesturecognizers
{
  //PRINT_SIGNATURE();
  // tap side of siri remote pad
  auto upRecognizer = [[UITapGestureRecognizer alloc]
                       initWithTarget: self action: @selector(tapUpArrowPressed:)];
  upRecognizer.allowedPressTypes  = @[[NSNumber numberWithInteger:UIPressTypeUpArrow]];
  upRecognizer.delegate = self;
  [m_glView addGestureRecognizer: upRecognizer];
  [upRecognizer release];
  
  auto downRecognizer = [[UITapGestureRecognizer alloc]
                         initWithTarget: self action: @selector(tapDownArrowPressed:)];
  downRecognizer.allowedPressTypes  = @[[NSNumber numberWithInteger:UIPressTypeDownArrow]];
  downRecognizer.delegate = self;
  [m_glView addGestureRecognizer: downRecognizer];
  [downRecognizer release];
  
  auto leftRecognizer = [[UITapGestureRecognizer alloc]
                         initWithTarget: self action: @selector(tapLeftArrowPressed:)];
  leftRecognizer.allowedPressTypes  = @[[NSNumber numberWithInteger:UIPressTypeLeftArrow]];
  leftRecognizer.delegate = self;
  [m_glView addGestureRecognizer: leftRecognizer];
  [leftRecognizer release];
  
  auto rightRecognizer = [[UITapGestureRecognizer alloc]
                          initWithTarget: self action: @selector(tapRightArrowPressed:)];
  rightRecognizer.allowedPressTypes  = @[[NSNumber numberWithInteger:UIPressTypeRightArrow]];
  rightRecognizer.delegate = self;
  [m_glView addGestureRecognizer: rightRecognizer];
  [rightRecognizer release];
}
//--------------------------------------------------------------
- (void)createPressGesturecognizers
{
  //PRINT_SIGNATURE();
  // we need UILongPressGestureRecognizer here because it will give
  // UIGestureRecognizerStateBegan AND UIGestureRecognizerStateEnded
  // even if we hold down for a long time. UITapGestureRecognizer
  // will eat the ending on long holds and we never see it.
  auto upRecognizer = [[UILongPressGestureRecognizer alloc]
    initWithTarget: self action: @selector(IRRemoteUpArrowPressed:)];
  upRecognizer.allowedPressTypes = @[[NSNumber numberWithInteger:UIPressTypeUpArrow]];
  upRecognizer.minimumPressDuration = 0.01;
  upRecognizer.delegate = self;
  [self.view addGestureRecognizer: upRecognizer];
  [upRecognizer release];

  auto downRecognizer = [[UILongPressGestureRecognizer alloc]
    initWithTarget: self action: @selector(IRRemoteDownArrowPressed:)];
  downRecognizer.allowedPressTypes = @[[NSNumber numberWithInteger:UIPressTypeDownArrow]];
  downRecognizer.minimumPressDuration = 0.01;
  downRecognizer.delegate = self;
  [self.view addGestureRecognizer: downRecognizer];
  [downRecognizer release];

  auto leftRecognizer = [[UILongPressGestureRecognizer alloc]
    initWithTarget: self action: @selector(IRRemoteLeftArrowPressed:)];
  leftRecognizer.allowedPressTypes = @[[NSNumber numberWithInteger:UIPressTypeLeftArrow]];
  leftRecognizer.minimumPressDuration = 0.01;
  leftRecognizer.delegate = self;
  [self.view addGestureRecognizer: leftRecognizer];
  [leftRecognizer release];

  auto rightRecognizer = [[UILongPressGestureRecognizer alloc]
    initWithTarget: self action: @selector(IRRemoteRightArrowPressed:)];
  rightRecognizer.allowedPressTypes = @[[NSNumber numberWithInteger:UIPressTypeRightArrow]];
  rightRecognizer.minimumPressDuration = 0.01;
  rightRecognizer.delegate = self;
  [self.view addGestureRecognizer: rightRecognizer];
  [rightRecognizer release];
  
  // we always have these under tvos
  auto menuRecognizer = [[UITapGestureRecognizer alloc]
                         initWithTarget: self action: @selector(menuPressed:)];
  menuRecognizer.allowedPressTypes = @[[NSNumber numberWithInteger:UIPressTypeMenu]];
  menuRecognizer.delegate  = self;
  [m_glView addGestureRecognizer: menuRecognizer];
  [menuRecognizer release];
  
  auto playPauseRecognizer = [[UITapGestureRecognizer alloc]
                              initWithTarget: self action: @selector(playPausePressed:)];
  playPauseRecognizer.allowedPressTypes = @[[NSNumber numberWithInteger:UIPressTypePlayPause]];
  playPauseRecognizer.delegate  = self;
  [m_glView addGestureRecognizer: playPauseRecognizer];
  [playPauseRecognizer release];
  
  auto selectRecognizer = [[UILongPressGestureRecognizer alloc]
                          initWithTarget: self action: @selector(selectPressed:)];
  selectRecognizer.allowedPressTypes = @[[NSNumber numberWithInteger:UIPressTypeSelect]];
  selectRecognizer.minimumPressDuration = 0.01;
  selectRecognizer.delegate = self;
  [self.view addGestureRecognizer: selectRecognizer];
  [selectRecognizer release];
  
}

//--------------------------------------------------------------
- (void)buttonHoldSelect
{
  self.m_holdCounter++;
  [self.m_holdTimer invalidate];
  [self sendKeyDownUp:XBMCK_c];
}
//--------------------------------------------------------------
- (void) activateKeyboard:(UIView *)view
{
  //PRINT_SIGNATURE();
  [self.view addSubview:view];
  m_glView.userInteractionEnabled = NO;
}
//--------------------------------------------------------------
- (void) deactivateKeyboard:(UIView *)view
{
  //PRINT_SIGNATURE();
  [view removeFromSuperview];
  m_glView.userInteractionEnabled = YES; 
  [self becomeFirstResponder];
}
//--------------------------------------------------------------
- (void)menuPressed:(UITapGestureRecognizer *)sender
{
  switch (sender.state)
  {
    case UIGestureRecognizerStateBegan:
      break;
    case UIGestureRecognizerStateChanged:
      break;
    case UIGestureRecognizerStateEnded:
      if (g_windowManager.GetFocusedWindow() == WINDOW_FULLSCREEN_VIDEO)
        CApplicationMessenger::GetInstance().SendMsg(TMSG_MEDIA_STOP);
      else
        [self sendKeyDownUp:XBMCK_BACKSPACE];
      break;
    default:
      break;
  }
}
//--------------------------------------------------------------
- (void)selectPressed:(UITapGestureRecognizer *)sender
{
  // if we have clicked select while scrolling up/down we need to reset direction of pan
  m_clickResetPan = true;
  
  switch (sender.state)
  {
    case UIGestureRecognizerStateBegan:
      self.m_holdCounter = 0;
      self.m_holdTimer = [NSTimer scheduledTimerWithTimeInterval:1 target:self selector:@selector(buttonHoldSelect) userInfo:nil repeats:YES];
      break;
    case UIGestureRecognizerStateChanged:
      if (self.m_holdCounter > 1)
      {
        [self.m_holdTimer invalidate];
        [self sendKeyDownUp:XBMCK_c];
      }
      break;
    case UIGestureRecognizerStateEnded:
      [self.m_holdTimer invalidate];
      if (self.m_holdCounter < 1)
        [self sendKeyDownUp:XBMCK_RETURN];
      break;
    default:
      break;
  }
}

- (void)playPausePressed:(UITapGestureRecognizer *) sender
{
  switch (sender.state)
  {
    case UIGestureRecognizerStateBegan:
      break;
    case UIGestureRecognizerStateChanged:
      break;
    case UIGestureRecognizerStateEnded:
      [self sendKeyDownUp:XBMCK_MEDIA_PLAY_PAUSE];
      break;
    default:
      break;
  }
}

//--------------------------------------------------------------
- (IBAction)IRRemoteUpArrowPressed:(UIGestureRecognizer *)sender
{
  switch (sender.state)
  {
    case UIGestureRecognizerStateBegan:
      [self startKeyPressTimer:XBMCK_UP];
      break;
    case UIGestureRecognizerStateChanged:
      break;
    case UIGestureRecognizerStateEnded:
      [self stopKeyPressTimer];
      [self sendKeyUp:XBMCK_UP];
      break;
    default:
      break;
  }
}
//--------------------------------------------------------------
- (IBAction)IRRemoteDownArrowPressed:(UIGestureRecognizer *)sender
{
  switch (sender.state)
  {
    case UIGestureRecognizerStateBegan:
      [self startKeyPressTimer:XBMCK_DOWN];
      break;
    case UIGestureRecognizerStateChanged:
      break;
    case UIGestureRecognizerStateEnded:
      [self stopKeyPressTimer];
      [self sendKeyUp:XBMCK_DOWN];
      break;
    default:
      break;
  }
}
//--------------------------------------------------------------
- (IBAction)IRRemoteLeftArrowPressed:(UIGestureRecognizer *)sender
{
  switch (sender.state)
  {
    case UIGestureRecognizerStateBegan:
      [self startKeyPressTimer:XBMCK_LEFT];
      break;
    case UIGestureRecognizerStateChanged:
      break;
    case UIGestureRecognizerStateEnded:
      [self stopKeyPressTimer];
      [self sendKeyUp:XBMCK_LEFT];
      break;
    default:
      break;
  }
}
//--------------------------------------------------------------
- (IBAction)IRRemoteRightArrowPressed:(UIGestureRecognizer *)sender
{
  switch (sender.state)
  {
    case UIGestureRecognizerStateBegan:
      [self startKeyPressTimer:XBMCK_RIGHT];
      break;
    case UIGestureRecognizerStateChanged:
      break;
    case UIGestureRecognizerStateEnded:
      [self stopKeyPressTimer];
      [self sendKeyUp:XBMCK_RIGHT];
      break;
    default:
      break;
  }
}

//--------------------------------------------------------------
- (IBAction)tapUpArrowPressed:(UIGestureRecognizer *)sender
{
  [self sendKeyDownUp:XBMCK_UP];
}
//--------------------------------------------------------------
- (IBAction)tapDownArrowPressed:(UIGestureRecognizer *)sender
{
  [self sendKeyDownUp:XBMCK_DOWN];
}
//--------------------------------------------------------------
- (IBAction)tapLeftArrowPressed:(UIGestureRecognizer *)sender
{
  [self sendKeyDownUp:XBMCK_LEFT];
}
//--------------------------------------------------------------
- (IBAction)tapRightArrowPressed:(UIGestureRecognizer *)sender
{
  [self sendKeyDownUp:XBMCK_RIGHT];
}

//--------------------------------------------------------------
- (IBAction)handlePan:(UIPanGestureRecognizer *)sender 
{
  if (m_appAlive == YES) //NO GESTURES BEFORE WE ARE UP AND RUNNING
  {
#if (NEW_REMOTE_HANDLING)
  XBMCKey key;
  switch (sender.state)
  {
    case UIGestureRecognizerStateBegan:
    {
      m_currentClick = -1;
      m_currentKey = XBMCK_UNKNOWN;
      break;
    }
    case UIGestureRecognizerStateChanged:
    {
      CGPoint gesturePoint = [sender translationInView:m_glView];
      gesturePoint.x = gesturePoint.x/1.92;
      gesturePoint.y = gesturePoint.y/1.08;
      
      key = [self getPanDirection:gesturePoint];
      
      int click;
      int absX = gesturePoint.x;
      int absY = gesturePoint.y;
        
      if (absX < 0)
        absX *= -1;
        
      if (absY < 0)
        absY *= -1;
        
      if (key == XBMCK_RIGHT || key == XBMCK_LEFT)
      {
        if (absX > 200)
          click = 2;
        else if (absX > 70)
          click = 1;
        else
          click = 0;
      }
      else
      {
        if (absY > 200)
          click = 2;
        else if (absY > 100)
          click = 1;
        else
          click = 0;
      }
        
      if (m_clickResetPan || m_currentKey != key || click != m_currentClick)
      {
        [self stopKeyPressTimer];
        [self sendKeyUp:m_currentKey];
          
        if (click != m_currentClick)
        {
          m_currentClick = click;
        }
        if (m_currentKey == XBMCK_UNKNOWN || m_clickResetPan ||
            ((m_currentKey == XBMCK_RIGHT && key == XBMCK_LEFT) ||
             (m_currentKey == XBMCK_LEFT && key == XBMCK_RIGHT) ||
             (m_currentKey == XBMCK_UP && key == XBMCK_DOWN) ||
             (m_currentKey == XBMCK_DOWN && key == XBMCK_UP))
            )
        {
          m_clickResetPan = false;
          m_currentKey = key;
        }
          
        if (m_currentClick == 2)
        {
          //fast click
          [self startKeyPressTimer:m_currentKey clickTime:0.20];
          LOG("fast click");
        }
        else if (m_currentClick == 1)
        {
          // slow click
          [self startKeyPressTimer:m_currentKey clickTime:0.80];
          LOG("slow click");
        }
      }
      break;
    }
    case UIGestureRecognizerStateEnded:
    case UIGestureRecognizerStateCancelled:
      [self stopKeyPressTimer];
      break;
    default:
      break;
  }
}
#else
  XBMCKey key;
  switch (sender.state)
  {
    case UIGestureRecognizerStateBegan:
    {
      m_touchBeginSignaled = false;
      break;
    }
    case UIGestureRecognizerStateChanged:
    {
      if (!m_touchBeginSignaled && m_touchDirection)
      {
        switch (m_touchDirection)
        {
          case UISwipeGestureRecognizerDirectionRight:
            key = XBMCK_RIGHT;
            break;
          case UISwipeGestureRecognizerDirectionLeft:
            key = XBMCK_LEFT;
            break;
          case UISwipeGestureRecognizerDirectionUp:
            key = XBMCK_UP;
            break;
          case UISwipeGestureRecognizerDirectionDown:
            key = XBMCK_DOWN;
            break;
          default:
            break;
        }
        m_touchBeginSignaled = true;
        [self startKeyPressTimer:key];
      }
      break;
    }
    case UIGestureRecognizerStateEnded:
    case UIGestureRecognizerStateCancelled:
      if (m_touchBeginSignaled)
      {
        m_touchBeginSignaled = false;
        m_touchDirection = NULL;
        [self stopKeyPressTimer];
        [self sendKeyUp:key];
      }
      break;
    default:
      break;
  }
}
#endif
}

//--------------------------------------------------------------
- (IBAction)handleSwipe:(UISwipeGestureRecognizer *)sender
{
  if(m_appAlive == YES)//NO GESTURES BEFORE WE ARE UP AND RUNNING
  {
#if (NEW_REMOTE_HANDLING)
    switch ([sender direction])
    {
      case UISwipeGestureRecognizerDirectionRight:
        [self sendKeyDownUp:XBMCK_RIGHT];
        break;
      case UISwipeGestureRecognizerDirectionLeft:
        [self sendKeyDownUp:XBMCK_LEFT];
        break;
      case UISwipeGestureRecognizerDirectionUp:
        [self sendKeyDownUp:XBMCK_UP];
        break;
      case UISwipeGestureRecognizerDirectionDown:
        [self sendKeyDownUp:XBMCK_DOWN];
        break;
    }
#else
    // remove if we go with new remote function
    m_touchDirection = [sender direction];
#endif
  }
}

#pragma mark -
- (void) insertVideoView:(UIView*)view
{
  [self.view insertSubview:view belowSubview:m_glView];
  [self.view setNeedsDisplay];
}

- (void) removeVideoView:(UIView*)view
{
  [view removeFromSuperview];
}

- (id)initWithFrame:(CGRect)frame withScreen:(UIScreen *)screen
{ 
  //PRINT_SIGNATURE();
  m_screenIdx = 0;
  self = [super init];
  if (!self)
    return nil;

  m_pause = FALSE;
  m_appAlive = FALSE;
  m_animating = FALSE;
  m_readyToRun = FALSE;

  m_isPlayingBeforeInactive = NO;
  m_bgTask = UIBackgroundTaskInvalid;
  m_playbackState = TVOS_PLAYBACK_STOPPED;

  m_window = [[UIWindow alloc] initWithFrame:frame];
  [m_window setRootViewController:self];  
  m_window.screen = screen;
  m_window.backgroundColor = [UIColor blackColor];
  // Turn off autoresizing
  m_window.autoresizingMask = 0;
  m_window.autoresizesSubviews = NO;

  [self enableScreenSaver];

  NSNotificationCenter *center = [NSNotificationCenter defaultCenter];
  [center addObserver: self
     selector: @selector(observeDefaultCenterStuff:) name: nil object: nil];

  [m_window makeKeyAndVisible];
  g_xbmcController = self;  

  return self;
}
//--------------------------------------------------------------
- (void)dealloc
{
  // stop background task

  [self stopAnimation];
  [m_glView release];
  [m_window release];
  
  NSNotificationCenter *center;
  // take us off the default center for our app
  center = [NSNotificationCenter defaultCenter];
  [center removeObserver: self];
  
  [super dealloc];
}
//--------------------------------------------------------------
- (void)loadView
{
  [super loadView];

  self.view.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
  self.view.autoresizesSubviews = YES;
  
  m_glView = [[MainEAGLView alloc] initWithFrame:self.view.bounds withScreen:[UIScreen mainScreen]];

  // Check if screen is Retina
  m_screenScale = [[UIScreen mainScreen] nativeScale];

  [self.view addSubview: m_glView];
}
//--------------------------------------------------------------
- (void)viewDidLoad
{
  [super viewDidLoad];

  [self createSwipeGestureRecognizers];
  [self createPanGestureRecognizers];
  [self createPressGesturecognizers];
  [self createTapGesturecognizers];
}
//--------------------------------------------------------------
- (void)viewWillAppear:(BOOL)animated
{
  //PRINT_SIGNATURE();
  [self resumeAnimation];
  [super viewWillAppear:animated];
}
//--------------------------------------------------------------
- (void)viewDidAppear:(BOOL)animated
{
  [super viewDidAppear:animated];
  [self becomeFirstResponder];
  [[UIApplication sharedApplication] beginReceivingRemoteControlEvents];
}
//--------------------------------------------------------------
- (void)viewWillDisappear:(BOOL)animated
{  
  //PRINT_SIGNATURE();
  [self pauseAnimation];
  [super viewWillDisappear:animated];
}
//--------------------------------------------------------------
- (void)viewDidUnload
{
  [[UIApplication sharedApplication] endReceivingRemoteControlEvents];
  [self resignFirstResponder];
  [super viewDidUnload];
}
//--------------------------------------------------------------
- (UIView *)inputView
{
  // override our input view to an empty view
  // this prevents the on screen keyboard
  // which would be shown whenever this UIResponder
  // becomes the first responder (which is always the case!)
  // caused by implementing the UIKeyInput protocol
  return [[[UIView alloc] initWithFrame:CGRectZero] autorelease];
}
//--------------------------------------------------------------
- (BOOL)canBecomeFirstResponder
{
  return YES;
}
//--------------------------------------------------------------
- (void)setFramebuffer
{
  if (!m_pause)
    [m_glView setFramebuffer];
}
//--------------------------------------------------------------
- (bool)presentFramebuffer
{
  if (!m_pause)
    return [m_glView presentFramebuffer];
  else
    return FALSE;
}
//--------------------------------------------------------------
- (CGSize)getScreenSize
{
  m_screensize.width  = m_glView.bounds.size.width  * m_screenScale;
  m_screensize.height = m_glView.bounds.size.height * m_screenScale;
  return m_screensize;
}

//--------------------------------------------------------------
- (void)didReceiveMemoryWarning
{
  // Releases the view if it doesn't have a superview.
  [super didReceiveMemoryWarning];
  // Release any cached data, images, etc. that aren't in use.
}
//--------------------------------------------------------------
- (void)disableSystemSleep
{
}
//--------------------------------------------------------------
- (void)enableSystemSleep
{
}
//--------------------------------------------------------------
- (void)disableScreenSaver
{
  m_disableIdleTimer = YES;
  [[UIApplication sharedApplication] setIdleTimerDisabled:YES];
}
//--------------------------------------------------------------
- (void)enableScreenSaver
{
  m_disableIdleTimer = NO;
  [[UIApplication sharedApplication] setIdleTimerDisabled:NO];
}

//--------------------------------------------------------------
- (void)resetSystemIdleTimer
{
  //PRINT_SIGNATURE();
  // this is silly :)
  // when system screen saver kicks off, we switch to UIApplicationStateInactive, the only way
  // to get out of the screensaver is to call ourself to open an custom URL that is registered
  // in our Info.plist. The openURL method of UIApplication must be supported but we can just
  // reply NO and we get restored to UIApplicationStateActive.
  if ([UIApplication sharedApplication].applicationState == UIApplicationStateInactive)
  {
    NSURL *url = [NSURL URLWithString:@"kodi://wakeup"];
    [[UIApplication sharedApplication] openURL:url];
  }
}

//--------------------------------------------------------------
- (UIScreenMode*) preferredScreenMode:(UIScreen*) screen
{
  // tvOS only support one mode, the current one.
  return [screen currentMode];
}

//--------------------------------------------------------------
- (NSArray<UIScreenMode *> *) availableScreenModes:(UIScreen*) screen
{
  // tvOS only support one mode, the current one,
  // pass back an array with this inside.
  NSMutableArray *array = [[[NSMutableArray alloc] initWithCapacity:1] autorelease];
  [array addObject:[screen currentMode]];
  return array;
}

//--------------------------------------------------------------
- (bool)changeScreen:(unsigned int)screenIdx withMode:(UIScreenMode *)mode
{
  return true;
}
//--------------------------------------------------------------
- (void)enterBackground
{
  //PRINT_SIGNATURE();
  if (g_application.m_pPlayer->IsPlaying() && !g_application.m_pPlayer->IsPaused())
  {
    m_isPlayingBeforeInactive = YES;
    CApplicationMessenger::GetInstance().SendMsg(TMSG_MEDIA_PAUSE_IF_PLAYING);
  }
  g_Windowing.OnAppFocusChange(false);
}

- (void)enterForeground
{
  //PRINT_SIGNATURE();
  g_Windowing.OnAppFocusChange(true);
  // when we come back, restore playing if we were.
  if (m_isPlayingBeforeInactive)
  {
    CApplicationMessenger::GetInstance().SendMsg(TMSG_MEDIA_UNPAUSE);
    m_isPlayingBeforeInactive = NO;
	[self disableScreenSaver];
  }
  else
  {
    [self enableScreenSaver];
  }
  
}

- (void)becomeInactive
{
  //PRINT_SIGNATURE();
  // if we were interrupted, already paused here
  // else if user background us or lock screen, only pause video here, audio keep playing.
  if (g_application.m_pPlayer->IsPlayingVideo() &&
     !g_application.m_pPlayer->IsPaused())
  {
    m_isPlayingBeforeInactive = YES;
    CApplicationMessenger::GetInstance().SendMsg(TMSG_MEDIA_PAUSE_IF_PLAYING);
  }
}

#pragma mark - MCRuntimeLib routines
//--------------------------------------------------------------
- (void)pauseAnimation
{
  //PRINT_SIGNATURE();
  m_pause = TRUE;
  g_application.SetRenderGUI(false);
}
//--------------------------------------------------------------
- (void)resumeAnimation
{
  //PRINT_SIGNATURE();
  m_pause = FALSE;
  g_application.SetRenderGUI(true);
}
//--------------------------------------------------------------
- (void)startAnimation
{
  //PRINT_SIGNATURE();
  if (m_animating == NO && [m_glView getContext])
  {
    // kick off an animation thread
    m_animationThreadLock = [[NSConditionLock alloc] initWithCondition: FALSE];
    m_animationThread = [[NSThread alloc] initWithTarget:self
      selector:@selector(runAnimation:) object:m_animationThreadLock];
    [m_animationThread start];
    m_animating = TRUE;
  }
}
//--------------------------------------------------------------
- (void)stopAnimation
{
  //PRINT_SIGNATURE();
  if (m_animating == NO && [m_glView getContext])
  {
    m_appAlive = FALSE;
    m_animating = FALSE;
    if (!g_application.m_bStop)
    {
      CApplicationMessenger::GetInstance().PostMsg(TMSG_QUIT);
    }
    // wait for animation thread to die
    if ([m_animationThread isFinished] == NO)
      [m_animationThreadLock lockWhenCondition:TRUE];
  }
}

int KODI_Run(bool renderGUI)
{
  int status = -1;
  
  //this can't be set from CAdvancedSettings::Initialize()
  //because it will overwrite the loglevel set with the --debug flag
#ifdef _DEBUG
  g_advancedSettings.m_logLevel     = LOG_LEVEL_DEBUG;
  g_advancedSettings.m_logLevelHint = LOG_LEVEL_DEBUG;
#else
  g_advancedSettings.m_logLevel     = LOG_LEVEL_NORMAL;
  g_advancedSettings.m_logLevelHint = LOG_LEVEL_NORMAL;
#endif
  CLog::SetLogLevel(g_advancedSettings.m_logLevel);
  
  // not a failure if returns false, just means someone
  // did the init before us.
  if (!g_advancedSettings.Initialized())
    g_advancedSettings.Initialize();
  
  if (!g_application.Create())
  {
    ELOG(@"ERROR: Unable to create application. Exiting");
    return status;
  }
  
  if (renderGUI && !g_application.CreateGUI())
  {
    ELOG(@"ERROR: Unable to create GUI. Exiting");
    return status;
  }
  if (!g_application.Initialize())
  {
    ELOG(@"ERROR: Unable to Initialize. Exiting");
    return status;
  }
  
  try
  {
    status = g_application.Run();
  }
  catch(...)
  {
    ELOG(@"ERROR: Exception caught on main loop. Exiting");
    status = -1;
  }

  return status;
}

//--------------------------------------------------------------
- (void)runAnimation:(id)arg
{
  CCocoaAutoPool outerpool;
  [[NSThread currentThread] setName:@"XBMC_Run"];
  
  // signal the thread is alive
  NSConditionLock* myLock = arg;
  [myLock lock];
  
  // Prevent child processes from becoming zombies on exit
  // if not waited upon. See also Util::Command
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_NOCLDWAIT;
  sa.sa_handler = SIG_IGN;
  sigaction(SIGCHLD, &sa, NULL);
  
  setlocale(LC_NUMERIC, "C");
  
  m_readyToRun = TRUE;
  int status = 0;
  try
  {
    // set up some MCRuntimeLib specific relationships
    XBMC::Context run_context;
    m_appAlive = TRUE;
    // start up with gui enabled
    status = KODI_Run(true);
    // we exited or died.
    g_application.SetRenderGUI(false);
  }
  catch(...)
  {
    m_appAlive = FALSE;
    ELOG(@"%sException caught on main loop status=%d. Exiting", __PRETTY_FUNCTION__, status);
  }
  // signal the thread is dead
  [myLock unlockWithCondition:TRUE];
  
  [self enableScreenSaver];
  [self enableSystemSleep];
  [self performSelectorOnMainThread:@selector(CallExit) withObject:nil  waitUntilDone:NO];
}

- (void) CallExit
{
  exit(0);
}

#pragma mark - remote control routines
//--------------------------------------------------------------
- (void)remoteControlReceivedWithEvent:(UIEvent*)receivedEvent
{
  //LOG(@"%s: type %ld, subtype: %d", __PRETTY_FUNCTION__, (long)receivedEvent.type, (int)receivedEvent.subtype);
  if (receivedEvent.type == UIEventTypeRemoteControl)
  {
    switch (receivedEvent.subtype)
    {
      case UIEventSubtypeRemoteControlTogglePlayPause:
        CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_PLAYER_PLAYPAUSE)));
        break;
      case UIEventSubtypeRemoteControlPlay:
        CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_PLAYER_PLAY)));
        break;
      case UIEventSubtypeRemoteControlPause:
        // ACTION_PAUSE sometimes cause unpause, use MediaPauseIfPlaying to make sure pause only
        //CApplicationMessenger::GetInstance().SendMsg(TMSG_MEDIA_PAUSE);
        // warning, something is wacky, in tvOS we only get this if play/pause button is pushed
        // the playPausePressed method should be getting called and it does, sometimes. WTF ?
        CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_PLAYER_PLAYPAUSE)));
        break;
      case UIEventSubtypeRemoteControlStop:
        CApplicationMessenger::GetInstance().SendMsg(TMSG_MEDIA_STOP);
        break;
      case UIEventSubtypeRemoteControlNextTrack:
        CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_NEXT_ITEM)));
        break;
      case UIEventSubtypeRemoteControlPreviousTrack:
        CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_PREV_ITEM)));
        break;
      case UIEventSubtypeRemoteControlBeginSeekingForward:
        // use 4X speed forward.
        CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_PLAYER_FORWARD)));
        CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_PLAYER_FORWARD)));
        break;
      case UIEventSubtypeRemoteControlBeginSeekingBackward:
        // use 4X speed rewind.
        CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_PLAYER_REWIND)));
        CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_PLAYER_REWIND)));
        break;
      case UIEventSubtypeRemoteControlEndSeekingForward:
      case UIEventSubtypeRemoteControlEndSeekingBackward:
        // restore to normal playback speed.
        if (g_application.m_pPlayer->IsPlaying() && !g_application.m_pPlayer->IsPaused())
          CApplicationMessenger::GetInstance().SendMsg(TMSG_GUI_ACTION, WINDOW_INVALID, -1, static_cast<void*>(new CAction(ACTION_PLAYER_PLAY)));
        break;
      default:
        //LOG(@"unhandled subtype: %d", (int)receivedEvent.subtype);
        break;
    }
  }
}

#pragma mark - private helper methods
- (void)observeDefaultCenterStuff:(NSNotification *)notification
{
//  LOG(@"default: %@", [notification name]);
//  LOG(@"userInfo: %@", [notification userInfo]);
}

@end
