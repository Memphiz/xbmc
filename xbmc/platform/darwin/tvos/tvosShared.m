/*
 *      Copyright (C) 2016 Daniel Radtke
 *      http://github.com/dantheman827/
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
 */

#import <Foundation/Foundation.h>

@interface tvosShared : NSObject
+ (NSString *)getSharedID;
@end

@implementation tvosShared : NSObject
+ (NSString *)getSharedID {
  NSString *bundleID;
  NSBundle *bundle = [NSBundle mainBundle];
  if ([[bundle.bundleURL pathExtension] isEqualToString:@"appex"]) { // We're in a extension
    // Peel off two directory levels - Kodi.app/PlugIns/MY_APP_EXTENSION.appex
    bundle = [NSBundle bundleWithURL:[[bundle.bundleURL URLByDeletingLastPathComponent] URLByDeletingLastPathComponent]];
    bundleID = bundle.bundleIdentifier;
  } else {
    bundleID = [NSBundle mainBundle].bundleIdentifier;
  }
  return [@"group." stringByAppendingString:bundleID];
}
@end
