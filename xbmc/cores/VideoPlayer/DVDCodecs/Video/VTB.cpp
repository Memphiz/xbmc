/*
 *      Copyright (C) 2005-2016 Team XBMC
 *      http://xbmc.org
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation; either
 *  version 2.1 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with XBMC; see the file COPYING.  If not, see
 *  <http://www.gnu.org/licenses/>.
 *
 */
#include "system.h"
#ifdef TARGET_DARWIN
#include "platform/darwin/osx/CocoaInterface.h"
#include "platform/darwin/DarwinUtils.h"
#include "cores/VideoPlayer/Process/ProcessInfo.h"
#include "DVDVideoCodec.h"
#include "DVDCodecs/DVDCodecUtils.h"
#include "utils/log.h"
#include "VTB.h"
#include "utils/BitstreamConverter.h"
#include "DVDClock.h"

extern "C" {
#include "libavcodec/videotoolbox.h"
#include "libswscale/swscale.h"
}

using namespace VTB;


CDecoder::CDecoder(CProcessInfo& processInfo) : m_processInfo(processInfo)
{
  m_avctx = nullptr;
  memset(&m_videobuffer, 0, sizeof(DVDVideoPicture));
}

CDecoder::~CDecoder()
{
  Close();
}

void CDecoder::Close()
{
  if (m_avctx)
  {
    av_videotoolbox_default_free(m_avctx);
    m_avctx = nullptr;
  }
  
  
  if (m_videobuffer.iFlags & DVP_FLAG_ALLOCATED)
  {
    free(m_videobuffer.data[0]), m_videobuffer.data[0] = NULL;
    free(m_videobuffer.data[1]), m_videobuffer.data[1] = NULL;
    free(m_videobuffer.data[2]), m_videobuffer.data[2] = NULL;
    m_videobuffer.iFlags = 0;
  }
}

bool CDecoder::Open(AVCodecContext *avctx, AVCodecContext* mainctx, enum AVPixelFormat fmt, unsigned int surfaces)
{
  if (avctx->codec_id == AV_CODEC_ID_H264)
  {
    CBitstreamConverter bs;
    if (!bs.Open(avctx->codec_id, (uint8_t*)avctx->extradata, avctx->extradata_size, false))
    {
      return false;
    }
    CFDataRef avcCData = CFDataCreate(kCFAllocatorDefault,
                            (const uint8_t*)bs.GetExtraData(), bs.GetExtraSize());
    bool interlaced = true;
    int max_ref_frames;
    uint8_t *spc = (uint8_t*)CFDataGetBytePtr(avcCData) + 6;
    uint32_t sps_size = BS_RB16(spc);
    if (sps_size)
      bs.parseh264_sps(spc+3, sps_size-1, &interlaced, &max_ref_frames);
    CFRelease(avcCData);
    if (interlaced)
    {
      CLog::Log(LOGNOTICE, "%s - possible interlaced content.", __FUNCTION__);
      return false;
    }
  }

  if (av_videotoolbox_default_init(avctx) < 0)
    return false;

  m_avctx = avctx;

  mainctx->pix_fmt = fmt;
  mainctx->hwaccel_context = avctx->hwaccel_context;

  m_processInfo.SetVideoDeintMethod("none");
  
  
  // allocate a YV12 DVDVideoPicture buffer.
  // first make sure all properties are reset.
  memset(&m_videobuffer, 0, sizeof(DVDVideoPicture));
  int width = avctx->width;
  int height = avctx->height;
  unsigned int iPixels = width * height;
  unsigned int iChromaPixels = iPixels/4;
  
  m_videobuffer.dts = DVD_NOPTS_VALUE;
  m_videobuffer.pts = DVD_NOPTS_VALUE;
  m_videobuffer.iFlags = DVP_FLAG_ALLOCATED;
  m_videobuffer.format = RENDER_FMT_YUV420P;
  m_videobuffer.color_range  = 0;
  m_videobuffer.color_matrix = 4;
  m_videobuffer.iWidth  = width;
  m_videobuffer.iHeight = height;
  m_videobuffer.iDisplayWidth  = width;
  m_videobuffer.iDisplayHeight = height;
  
  m_videobuffer.iLineSize[0] = width;   //Y
  m_videobuffer.iLineSize[1] = width/2; //U
  m_videobuffer.iLineSize[2] = width/2; //V
  m_videobuffer.iLineSize[3] = 0;
  
  m_videobuffer.data[0] = (uint8_t*)malloc(16 + iPixels);
  m_videobuffer.data[1] = (uint8_t*)malloc(16 + iChromaPixels);
  m_videobuffer.data[2] = (uint8_t*)malloc(16 + iChromaPixels);
  m_videobuffer.data[3] = NULL;
  
  // set all data to 0 for less artifacts.. hmm.. what is black in YUV??
  memset(m_videobuffer.data[0], 0, iPixels);
  memset(m_videobuffer.data[1], 0, iChromaPixels);
  memset(m_videobuffer.data[2], 0, iChromaPixels);
  
  return true;
}

int CDecoder::Decode(AVCodecContext* avctx, AVFrame* frame)
{
  int status = Check(avctx);
  if(status)
    return status;

  if(frame)
    return VC_BUFFER | VC_PICTURE;
  else
    return VC_BUFFER;
}

void CDecoder::UYVY422_to_YUV420P(uint8_t *yuv422_ptr, int yuv422_stride, DVDVideoPicture *picture)
{
  // convert PIX_FMT_UYVY422 to PIX_FMT_YUV420P.
  struct SwsContext *swcontext = sws_getContext(
                                                m_videobuffer.iWidth, m_videobuffer.iHeight, AV_PIX_FMT_UYVY422,
                                                m_videobuffer.iWidth, m_videobuffer.iHeight, AV_PIX_FMT_YUV420P,
                                                SWS_FAST_BILINEAR, NULL, NULL, NULL);
  if (swcontext)
  {
    uint8_t  *src[] = { yuv422_ptr, 0, 0, 0 };
    int srcStride[] = { yuv422_stride, 0, 0, 0 };
    
    uint8_t  *dst[] = { picture->data[0], picture->data[1], picture->data[2], 0 };
    int dstStride[] = { picture->iLineSize[0], picture->iLineSize[1], picture->iLineSize[2], 0 };
    
    sws_scale(swcontext, src, srcStride, 0, picture->iHeight, dst, dstStride);
    sws_freeContext(swcontext);
  }
}


bool CDecoder::GetPicture(AVCodecContext* avctx, AVFrame* frame, DVDVideoPicture* picture)
{
  ((CDVDVideoCodecFFmpeg*)avctx->opaque)->GetPictureCommon(picture);

  // CVBREF - render with iosurface/zerocopy
  //picture->format = RENDER_FMT_CVBREF;
  //picture->cvBufferRef = (CVPixelBufferRef)frame->data[3];
  
  //convert buffer to 420p, allows glsl rendering
  FourCharCode pixel_buffer_format = kCVPixelFormatType_422YpCbCr8;
  CVPixelBufferRef picture_buffer_ref = (CVPixelBufferRef)frame->data[3];
  
  // clone the video picture buffer settings.
  *picture = m_videobuffer;
  
  // lock the CVPixelBuffer down
  CVPixelBufferLockBaseAddress(picture_buffer_ref, 0);
  int row_stride = CVPixelBufferGetBytesPerRowOfPlane(picture_buffer_ref, 0);
  int width = CVPixelBufferGetWidth(picture_buffer_ref);
  int height = CVPixelBufferGetHeight(picture_buffer_ref);
  uint8_t *base_ptr = (uint8_t*)CVPixelBufferGetBaseAddressOfPlane(picture_buffer_ref, 0);
  if (base_ptr)
  {
    if (pixel_buffer_format == kCVPixelFormatType_422YpCbCr8)
    {
      //UYVY422_to_YUV420P(base_ptr, row_stride, picture);
      picture->data[0] = base_ptr;
      picture->iLineSize[0] = row_stride;
      picture->iWidth = width;
      picture->iHeight = height;
      picture->format = RENDER_FMT_UYVY422;
    }
    //else if (pixel_buffer_format == kCVPixelFormatType_32BGRA)
    //  BGRA_to_YUV420P(base_ptr, row_stride, pDvdVideoPicture);
  }
  // unlock the CVPixelBuffer
  CVPixelBufferUnlockBaseAddress(picture_buffer_ref, 0);

  return true;
}

int CDecoder::Check(AVCodecContext* avctx)
{
  return 0;
}

unsigned CDecoder::GetAllowedReferences()
{
  //return 5;
  return 0;
}

#endif
