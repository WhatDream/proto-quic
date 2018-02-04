// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/tools/quic/quic_simple_server_stream.h"

#include <list>
#include <utility>

#include "net/quic/core/quic_spdy_stream.h"
#include "net/quic/core/spdy_utils.h"
#include "net/quic/platform/api/quic_bug_tracker.h"
#include "net/quic/platform/api/quic_flags.h"
#include "net/quic/platform/api/quic_logging.h"
#include "net/quic/platform/api/quic_map_util.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/spdy/core/spdy_protocol.h"
#include "net/tools/quic/quic_http_response_cache.h"
#include "net/tools/quic/quic_simple_server_session.h"

using std::string;

namespace net {

QuicSimpleServerStream::QuicSimpleServerStream(
    QuicStreamId id,
    QuicSpdySession* session,
    QuicHttpResponseCache* response_cache)
    : QuicSpdyServerStreamBase(id, session),
      content_length_(-1),
      response_cache_(response_cache) {

        //blitzhong
        //2017-10-20
        struct sockaddr_in serverAddr;
        socklen_t addr_size;
        /*---- Create the socket. The three arguments are: ----*/
        /* 1) Internet domain 2) Stream socket 3) Default protocol (TCP in this case) */
        clientSocket = socket(PF_INET, SOCK_STREAM, 0);
        
        /*---- Configure settings of the server address struct ----*/
        /* Address family = Internet */
        serverAddr.sin_family = AF_INET;
        /* Set port number, using htons function to use proper byte order */
        serverAddr.sin_port = htons(80);
        /* Set IP address to localhost */
        serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");
        /* Set all bits of the padding field to 0 */
        memset(serverAddr.sin_zero, '\0', sizeof serverAddr.sin_zero);  

        struct timeval timeout = {0,2};    
        setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,sizeof(struct timeval));

        /*---- Connect the socket to the server using the address struct ----*/
        addr_size = sizeof serverAddr;
        connect(clientSocket, (struct sockaddr *) &serverAddr, addr_size);
      }

QuicSimpleServerStream::~QuicSimpleServerStream() {}

void QuicSimpleServerStream::OnInitialHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QuicSpdyStream::OnInitialHeadersComplete(fin, frame_len, header_list);
  if (!SpdyUtils::CopyAndValidateHeaders(header_list, &content_length_,
                                         &request_headers_)) {
    QUIC_DVLOG(1) << "Invalid headers";
    SendErrorResponse();
  }
  ConsumeHeaderList();
}

void QuicSimpleServerStream::OnTrailingHeadersComplete(
    bool fin,
    size_t frame_len,
    const QuicHeaderList& header_list) {
  QUIC_BUG << "Server does not support receiving Trailers.";
  SendErrorResponse();
}

void QuicSimpleServerStream::OnDataAvailable() {
  while (HasBytesToRead()) {
    struct iovec iov;
    if (GetReadableRegions(&iov, 1) == 0) {
      // No more data to read.
      break;
    }
    QUIC_DVLOG(1) << "Stream " << id() << " processed " << iov.iov_len
                  << " bytes.";
    body_.append(static_cast<char*>(iov.iov_base), iov.iov_len);

    if (content_length_ >= 0 &&
        body_.size() > static_cast<uint64_t>(content_length_)) {
      QUIC_DVLOG(1) << "Body size (" << body_.size() << ") > content length ("
                    << content_length_ << ").";
      SendErrorResponse();
      return;
    }
    MarkConsumed(iov.iov_len);
  }
  if (!sequencer()->IsClosed()) {
    sequencer()->SetUnblocked();
    return;
  }

  // If the sequencer is closed, then all the body, including the fin, has been
  // consumed.
  OnFinRead();

  if (write_side_closed() || fin_buffered()) {
    return;
  }

  //added by blitzhong
  //2017-10-15
  proxy();

  SendResponse();
}

int QuicSimpleServerStream::proxy() {
  char buffer[8193]={0};
  int len, sendlen = 0;
  //int len;
  /*---- send the message from the server into the buffer ----*/
  len = body_.length();
  while(sendlen < len) {
    int n = send(clientSocket, body_.c_str() + sendlen, len - sendlen, 0);
    sendlen += n;
  }

  /*while(1) {
    len = recv(clientSocket, buffer, 8192, 0);
    if(len == 0) {
      fprintf(stdout, "connection closed!\n");
      break;
    } else if(len < 0) {
        if(errno != EAGAIN) {
            perror("recv");
        }
        break;
    } else {
      buffer[len] = '\0';
      respon_body+=buffer;
    }
  }
  
  printf("Data received: %d\n", (int)respon_body.length());*/

  int epoll_fd, nfds;  
  epoll_fd=epoll_create(1);  
  if(epoll_fd==-1)  
  {  
      perror("epoll_create failed");  
      exit(EXIT_FAILURE);  
  }
  struct epoll_event ev;
  ev.events=EPOLLIN|EPOLLET;  
  ev.data.fd=clientSocket; 

  if(epoll_ctl(epoll_fd, EPOLL_CTL_ADD, clientSocket, &ev)==-1)  
  {  
      perror("epll_ctl:server_sockfd register failed");  
      exit(EXIT_FAILURE);  
  } 

  while (1) {
    if((nfds = epoll_wait(epoll_fd, &ev, 1, 20)) == -1)  
    {  
      perror("start epoll_wait failed");  
      exit(EXIT_FAILURE);  
    } 
    else if(nfds > 0)
    {

      len = recv(clientSocket, buffer, 8192, 0);
      respon_body.append(buffer, len);

      while((len = recv(clientSocket, buffer, 8192, 0)) > 0) {
        buffer[len]='\0';
        respon_body.append(buffer, len);
      }
      printf("Data received: %d\n", (int)respon_body.length());
      continue;
    }
    else if(nfds <= 0)
    {
      if(epoll_ctl(epoll_fd, EPOLL_CTL_DEL, clientSocket, NULL)==-1)  
      {  
        perror("epll_ctl:server_sockfd del failed");  
        exit(EXIT_FAILURE);  
      } 
      close(clientSocket);
      break;

    }
  }
  
  close(epoll_fd);
  //printf("%s\n", body_.c_str());
  //send(clientSocket, body_.c_str(), len, 0);

  //if(strcmp(data, "quit") == 0) return 0;
  /*---- Read the message from the server into the buffer ----*/
  /*respon_body = "";
  //while((len = recv(clientSocket, buffer, 8192, 0)) > 0) {
  //    respon_body += buffer;
  //}

  respon_body += '\0';*/
  /*len = recv(clientSocket, buffer, 8192, 0);
  buffer[len]='\0';
  respon_body = buffer;*/
  return 0;
}


void QuicSimpleServerStream::PushResponse(
    SpdyHeaderBlock push_request_headers) {
  if (id() % 2 != 0) {
    QUIC_BUG << "Client initiated stream shouldn't be used as promised stream.";
    return;
  }
  // Change the stream state to emulate a client request.
  request_headers_ = std::move(push_request_headers);
  content_length_ = 0;
  QUIC_DVLOG(1) << "Stream " << id()
                << " ready to receive server push response.";

  // Set as if stream decompresed the headers and received fin.
  QuicSpdyStream::OnInitialHeadersComplete(/*fin=*/true, 0, QuicHeaderList());
}

void QuicSimpleServerStream::SendResponse() {
  if (request_headers_.empty()) {
    QUIC_DVLOG(1) << "Request headers empty.";
    SendErrorResponse();
    return;
  }

  if (content_length_ > 0 &&
      static_cast<uint64_t>(content_length_) != body_.size()) {
    QUIC_DVLOG(1) << "Content length (" << content_length_ << ") != body size ("
                  << body_.size() << ").";
    SendErrorResponse();
    return;
  }

  if (!QuicContainsKey(request_headers_, ":authority") ||
      !QuicContainsKey(request_headers_, ":path")) {
    QUIC_DVLOG(1) << "Request headers do not contain :authority or :path.";
    SendErrorResponse();
    return;
  }

  // Find response in cache. If not found, send error response.
  const QuicHttpResponseCache::Response* response = nullptr;
  auto authority = request_headers_.find(":authority");
  auto path = request_headers_.find(":path");
  if (authority != request_headers_.end() && path != request_headers_.end()) {
    response = response_cache_->GetResponse(authority->second, path->second);
  }
  if (response == nullptr) {
    QUIC_DVLOG(1) << "Response not found in cache.";
    SendNotFoundResponse();
    return;
  }

  if (response->response_type() == QuicHttpResponseCache::CLOSE_CONNECTION) {
    QUIC_DVLOG(1) << "Special response: closing connection.";
    CloseConnectionWithDetails(QUIC_NO_ERROR, "Toy server forcing close");
    return;
  }

  if (response->response_type() == QuicHttpResponseCache::IGNORE_REQUEST) {
    QUIC_DVLOG(1) << "Special response: ignoring request.";
    return;
  }

  // Examing response status, if it was not pure integer as typical h2
  // response status, send error response. Notice that
  // QuicHttpResponseCache push urls are strictly authority + path only,
  // scheme is not included (see |QuicHttpResponseCache::GetKey()|).
  string request_url = request_headers_[":authority"].as_string() +
                       request_headers_[":path"].as_string();
  int response_code;
  const SpdyHeaderBlock& response_headers = response->headers();
  if (!ParseHeaderStatusCode(response_headers, &response_code)) {
    auto status = response_headers.find(":status");
    if (status == response_headers.end()) {
      QUIC_LOG(WARNING)
          << ":status not present in response from cache for request "
          << request_url;
    } else {
      QUIC_LOG(WARNING) << "Illegal (non-integer) response :status from cache: "
                        << status->second << " for request " << request_url;
    }
    SendErrorResponse();
    return;
  }

  if (id() % 2 == 0) {
    // A server initiated stream is only used for a server push response,
    // and only 200 and 30X response codes are supported for server push.
    // This behavior mirrors the HTTP/2 implementation.
    bool is_redirection = response_code / 100 == 3;
    if (response_code != 200 && !is_redirection) {
      QUIC_LOG(WARNING) << "Response to server push request " << request_url
                        << " result in response code " << response_code;
      Reset(QUIC_STREAM_CANCELLED);
      return;
    }
  }
  std::list<QuicHttpResponseCache::ServerPushInfo> resources =
      response_cache_->GetServerPushResources(request_url);
  QUIC_DVLOG(1) << "Stream " << id() << " found " << resources.size()
                << " push resources.";

  if (!resources.empty()) {
    QuicSimpleServerSession* session =
        static_cast<QuicSimpleServerSession*>(spdy_session());
    session->PromisePushResources(request_url, resources, id(),
                                  request_headers_);
  }

  QUIC_DVLOG(1) << "Stream " << id() << " sending response.";

  //modified by blitzhong
  //2017-10-15
  //SendHeadersAndBodyAndTrailers(response->headers().Clone(), response->body(),
  //                              response->trailers().Clone());
  SendHeadersAndBodyAndTrailers(response->headers().Clone(), respon_body,
                                response->trailers().Clone());
}

void QuicSimpleServerStream::SendNotFoundResponse() {
  QUIC_DVLOG(1) << "Stream " << id() << " sending not found response.";
  SpdyHeaderBlock headers;
  headers[":status"] = "404";
  headers["content-length"] =
      QuicTextUtils::Uint64ToString(strlen(kNotFoundResponseBody));
  SendHeadersAndBody(std::move(headers), kNotFoundResponseBody);
}

void QuicSimpleServerStream::SendErrorResponse() {
  QUIC_DVLOG(1) << "Stream " << id() << " sending error response.";
  SpdyHeaderBlock headers;
  headers[":status"] = "500";
  headers["content-length"] =
      QuicTextUtils::Uint64ToString(strlen(kErrorResponseBody));
  SendHeadersAndBody(std::move(headers), kErrorResponseBody);
}

void QuicSimpleServerStream::SendHeadersAndBody(
    SpdyHeaderBlock response_headers,
    QuicStringPiece body) {
  SendHeadersAndBodyAndTrailers(std::move(response_headers), body,
                                SpdyHeaderBlock());
}

void QuicSimpleServerStream::SendHeadersAndBodyAndTrailers(
    SpdyHeaderBlock response_headers,
    QuicStringPiece body,
    SpdyHeaderBlock response_trailers) {
  // Send the headers, with a FIN if there's nothing else to send.
  bool send_fin = (body.empty() && response_trailers.empty());
  QUIC_DLOG(INFO) << "Stream " << id() << " writing headers (fin = " << send_fin
                  << ") : " << response_headers.DebugString();
  WriteHeaders(std::move(response_headers), send_fin, nullptr);
  if (send_fin) {
    // Nothing else to send.
    return;
  }

  // Send the body, with a FIN if there's no trailers to send.
  send_fin = response_trailers.empty();
  QUIC_DLOG(INFO) << "Stream " << id() << " writing body (fin = " << send_fin
                  << ") with size: " << body.size();
  if (!body.empty() || send_fin) {
    WriteOrBufferData(body, send_fin, nullptr);
  }
  if (send_fin) {
    // Nothing else to send.
    return;
  }

  // Send the trailers. A FIN is always sent with trailers.
  QUIC_DLOG(INFO) << "Stream " << id() << " writing trailers (fin = true): "
                  << response_trailers.DebugString();
  WriteTrailers(std::move(response_trailers), nullptr);
}

const char* const QuicSimpleServerStream::kErrorResponseBody = "bad";
const char* const QuicSimpleServerStream::kNotFoundResponseBody =
    "file not found";

}  // namespace net
