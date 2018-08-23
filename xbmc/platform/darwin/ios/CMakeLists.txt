set(SOURCES IOSEAGLView.mm
            IOSExternalTouchController.mm
            IOSKeyboard.mm
            IOSKeyboardView.mm
            IOSScreenManager.mm
            XBMCController.mm)

set(HEADERS IOSEAGLView.h
            IOSExternalTouchController.h
            IOSKeyboard.h
            IOSKeyboardView.h
            IOSScreenManager.h
            route.h
            XBMCApplication.h
            XBMCController.h
            XBMCDebugHelpers.h)

core_add_library(platform_ios)
