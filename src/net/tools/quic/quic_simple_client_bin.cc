// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
//   TODO(rtenneti): make --host optional by getting IP Address of URL's host.
//
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//
// Standard request/response:
//   quic_client http://www.google.com  --host=${IP}
//   quic_client http://www.google.com --quiet  --host=${IP}
//   quic_client https://www.google.com --port=443  --host=${IP}
//
// Use a specific version:
//   quic_client http://www.google.com --quic_version=23  --host=${IP}
//
// Send a POST instead of a GET:
//   quic_client http://www.google.com --body="this is a POST body" --host=${IP}
//
// Append additional headers to the request:
//   quic_client http://www.google.com  --host=${IP}
//               --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   Get IP address of the www.google.com
//   IP=`dig www.google.com +short | head -1`
//   quic_client mail.google.com --host=${IP}
//
// Try to connect to a host which does not speak QUIC:
//   Get IP address of the www.example.com
//   IP=`dig www.example.com +short | head -1`
//   quic_client http://www.example.com --host=${IP}

#include <iostream>
#include <queue> 
#include <arpa/inet.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>

#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/logging.h"
#include "base/message_loop/message_loop.h"
#include "net/base/net_errors.h"
#include "net/base/privacy_mode.h"
#include "net/cert/cert_verifier.h"
#include "net/cert/ct_known_logs.h"
#include "net/cert/ct_log_verifier.h"
#include "net/cert/multi_log_ct_verifier.h"
#include "net/http/transport_security_state.h"
#include "net/quic/chromium/crypto/proof_verifier_chromium.h"
#include "net/quic/core/quic_error_codes.h"
#include "net/quic/core/quic_packets.h"
#include "net/quic/core/quic_server_id.h"
#include "net/quic/platform/api/quic_socket_address.h"
#include "net/quic/platform/api/quic_str_cat.h"
#include "net/quic/platform/api/quic_string_piece.h"
#include "net/quic/platform/api/quic_text_utils.h"
#include "net/spdy/chromium/spdy_http_utils.h"
#include "net/spdy/core/spdy_header_block.h"
#include "net/tools/quic/quic_simple_client.h"
#include "net/tools/quic/synchronous_host_resolver.h"
#include "url/gurl.h"

using net::CertVerifier;
using net::CTPolicyEnforcer;
using net::CTVerifier;
using net::MultiLogCTVerifier;
using net::ProofVerifier;
using net::ProofVerifierChromium;
using net::QuicStringPiece;
using net::QuicTextUtils;
using net::SpdyHeaderBlock;
using net::TransportSecurityState;
using std::cout;
using std::cerr;
using std::endl;
using std::string;

// The IP or hostname the quic client will connect to.
string FLAGS_host = "";
// The port to connect to.
int32_t FLAGS_port = 0;
// If set, send a POST with this body.
string FLAGS_body = "";
// If set, contents are converted from hex to ascii, before sending as body of
// a POST. e.g. --body_hex=\"68656c6c6f\"
string FLAGS_body_hex = "";
// A semicolon separated list of key:value pairs to add to request headers.
string FLAGS_headers = "";
// Set to true for a quieter output experience.
bool FLAGS_quiet = false;
// QUIC version to speak, e.g. 21. If not set, then all available versions are
// offered in the handshake.
int32_t FLAGS_quic_version = -1;
// If true, a version mismatch in the handshake is not considered a failure.
// Useful for probing a server to determine if it speaks any version of QUIC.
bool FLAGS_version_mismatch_ok = false;
// If true, an HTTP response code of 3xx is considered to be a successful
// response, otherwise a failure.
bool FLAGS_redirect_is_success = true;
// Initial MTU of the connection.
int32_t FLAGS_initial_mtu = 0;

class FakeProofVerifier : public ProofVerifier {
 public:
  net::QuicAsyncStatus VerifyProof(
      const string& hostname,
      const uint16_t port,
      const string& server_config,
      net::QuicVersion quic_version,
      QuicStringPiece chlo_hash,
      const std::vector<string>& certs,
      const string& cert_sct,
      const string& signature,
      const net::ProofVerifyContext* context,
      string* error_details,
      std::unique_ptr<net::ProofVerifyDetails>* details,
      std::unique_ptr<net::ProofVerifierCallback> callback) override {
    return net::QUIC_SUCCESS;
  }

  net::QuicAsyncStatus VerifyCertChain(
      const std::string& hostname,
      const std::vector<std::string>& certs,
      const net::ProofVerifyContext* verify_context,
      std::string* error_details,
      std::unique_ptr<net::ProofVerifyDetails>* verify_details,
      std::unique_ptr<net::ProofVerifierCallback> callback) override {
    return net::QUIC_SUCCESS;
  }
};


//added by blitzhong
//2017-10-23

typedef struct _connector
{
  int fd;
  net::QuicSimpleClient *client;
} connector;

#define MAXEVENTS 1024

static int
make_socket_non_blocking (int sfd)
{
  int flags, s;

  flags = fcntl (sfd, F_GETFL, 0);
  if (flags == -1)
    {
      perror ("fcntl");
      return -1;
    }

  flags |= O_NONBLOCK;
  s = fcntl (sfd, F_SETFL, flags);
  if (s == -1)
    {
      perror ("fcntl");
      return -1;
    }

  return 0;
}

static int
create_and_bind (char *port)
{
  struct addrinfo hints;
  struct addrinfo *result, *rp;
  int s, sfd;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_UNSPEC;     /* Return IPv4 and IPv6 choices */
  hints.ai_socktype = SOCK_STREAM; /* We want a TCP socket */
  hints.ai_flags = AI_PASSIVE;     /* All interfaces */

  s = getaddrinfo (NULL, port, &hints, &result);
  if (s != 0)
  {
      fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
      return -1;
  }

  for (rp = result; rp != NULL; rp = rp->ai_next)
    {
      sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (sfd == -1)
        continue;

      s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
      if (s == 0)
        {
          /* We managed to bind successfully! */
          break;
        }

      close (sfd);
    }

  if (rp == NULL)
    {
      fprintf (stderr, "Could not bind\n");
      return -1;
    }

  freeaddrinfo (result);

  return sfd;
}



int main(int argc, char* argv[]) {

  base::CommandLine::Init(argc, argv);
  base::CommandLine* line = base::CommandLine::ForCurrentProcess();
  const base::CommandLine::StringVector& urls = line->GetArgs();

  logging::LoggingSettings settings;
  settings.logging_dest = logging::LOG_TO_SYSTEM_DEBUG_LOG;
  CHECK(logging::InitLogging(settings));

  if (line->HasSwitch("h") || line->HasSwitch("help") || urls.empty()) {
    const char* help_str =
        "Usage: quic_client [options] <url>\n"
        "\n"
        "<url> with scheme must be provided (e.g. http://www.google.com)\n\n"
        "Options:\n"
        "-h, --help                  show this help message and exit\n"
        "--host=<host>               specify the IP address of the hostname to "
        "connect to\n"
        "--port=<port>               specify the port to connect to\n"
        "--body=<body>               specify the body to post\n"
        "--body_hex=<body_hex>       specify the body_hex to be printed out\n"
        "--headers=<headers>         specify a semicolon separated list of "
        "key:value pairs to add to request headers\n"
        "--quiet                     specify for a quieter output experience\n"
        "--quic-version=<quic version> specify QUIC version to speak\n"
        "--version_mismatch_ok       if specified a version mismatch in the "
        "handshake is not considered a failure\n"
        "--redirect_is_success       if specified an HTTP response code of 3xx "
        "is considered to be a successful response, otherwise a failure\n"
        "--initial_mtu=<initial_mtu> specify the initial MTU of the connection"
        "\n"
        "--disable-certificate-verification do not verify certificates\n";
    cout << help_str;
    exit(0);
  }
  if (line->HasSwitch("host")) {
    FLAGS_host = line->GetSwitchValueASCII("host");
  }
  if (line->HasSwitch("port")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("port"), &FLAGS_port)) {
      std::cerr << "--port must be an integer\n";
      return 1;
    }
  }
  if (line->HasSwitch("body")) {
    FLAGS_body = line->GetSwitchValueASCII("body");
  }
  if (line->HasSwitch("body_hex")) {
    FLAGS_body_hex = line->GetSwitchValueASCII("body_hex");
  }
  if (line->HasSwitch("headers")) {
    FLAGS_headers = line->GetSwitchValueASCII("headers");
  }
  if (line->HasSwitch("quiet")) {
    FLAGS_quiet = true;
  }
  if (line->HasSwitch("quic-version")) {
    int quic_version;
    if (base::StringToInt(line->GetSwitchValueASCII("quic-version"),
                          &quic_version)) {
      FLAGS_quic_version = quic_version;
    }
  }
  if (line->HasSwitch("version_mismatch_ok")) {
    FLAGS_version_mismatch_ok = true;
  }
  if (line->HasSwitch("redirect_is_success")) {
    FLAGS_redirect_is_success = true;
  }
  if (line->HasSwitch("initial_mtu")) {
    if (!base::StringToInt(line->GetSwitchValueASCII("initial_mtu"),
                           &FLAGS_initial_mtu)) {
      std::cerr << "--initial_mtu must be an integer\n";
      return 1;
    }
  }


  VLOG(1) << "server host: " << FLAGS_host << " port: " << FLAGS_port
          << " body: " << FLAGS_body << " headers: " << FLAGS_headers
          << " quiet: " << FLAGS_quiet
          << " quic-version: " << FLAGS_quic_version
          << " version_mismatch_ok: " << FLAGS_version_mismatch_ok
          << " redirect_is_success: " << FLAGS_redirect_is_success
          << " initial_mtu: " << FLAGS_initial_mtu;

  base::AtExitManager exit_manager;
  base::MessageLoopForIO message_loop;

  // Determine IP address to connect to from supplied hostname.
  net::QuicIpAddress ip_addr;

  GURL url(urls[0]);
  string host = FLAGS_host;
  if (host.empty()) {
    host = url.host();
  }
  int port = FLAGS_port;
  if (port == 0) {
    port = url.EffectiveIntPort();
  }
  if (!ip_addr.FromString(host)) {
    net::AddressList addresses;
    int rv = net::SynchronousHostResolver::Resolve(host, &addresses);
    if (rv != net::OK) {
      LOG(ERROR) << "Unable to resolve '" << host
                 << "' : " << net::ErrorToShortString(rv);
      return 1;
    }
    ip_addr =
        net::QuicIpAddress(net::QuicIpAddressImpl(addresses[0].address()));
  }

  string host_port = net::QuicStrCat(ip_addr.ToString(), ":", port);
  VLOG(1) << "Resolved " << host << " to " << host_port << endl;

  // Build the client, and try to connect.
  /*net::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                              net::PRIVACY_MODE_DISABLED);
  net::QuicVersionVector versions = net::AllSupportedVersions();
  if (FLAGS_quic_version != -1) {
    versions.clear();
    versions.push_back(static_cast<net::QuicVersion>(FLAGS_quic_version));
  }
  // For secure QUIC we need to verify the cert chain.
  std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
  std::unique_ptr<TransportSecurityState> transport_security_state(
      new TransportSecurityState);
  std::unique_ptr<MultiLogCTVerifier> ct_verifier(new MultiLogCTVerifier());
  ct_verifier->AddLogs(net::ct::CreateLogVerifiersForKnownLogs());
  std::unique_ptr<CTPolicyEnforcer> ct_policy_enforcer(new CTPolicyEnforcer());
  std::unique_ptr<ProofVerifier> proof_verifier;
  if (line->HasSwitch("disable-certificate-verification")) {
    proof_verifier.reset(new FakeProofVerifier());
  } else {
    proof_verifier.reset(new ProofVerifierChromium(
        cert_verifier.get(), ct_policy_enforcer.get(),
        transport_security_state.get(), ct_verifier.get()));
  }

  net::QuicSimpleClient client(net::QuicSocketAddress(ip_addr, port), server_id,
                               versions, std::move(proof_verifier));
  client.set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : net::kDefaultMaxPacketSize);
  if (!client.Initialize()) {
    cerr << "Failed to initialize client." << endl;
    return 1;
  }
  if (!client.Connect()) {
    net::QuicErrorCode error = client.session()->error();
    if (FLAGS_version_mismatch_ok && error == net::QUIC_INVALID_VERSION) {
      cout << "Server talks QUIC, but none of the versions supported by "
           << "this client: " << QuicVersionVectorToString(versions) << endl;
      // Version mismatch is not deemed a failure.
      return 0;
    }
    cerr << "Failed to connect to " << host_port
         << ". Error: " << net::QuicErrorCodeToString(error) << endl;
    return 1;
  }
  cout << "Connected to " << host_port << endl;

  // Construct the string body from flags, if provided.
  string body = FLAGS_body;
  if (!FLAGS_body_hex.empty()) {
    DCHECK(FLAGS_body.empty()) << "Only set one of --body and --body_hex.";
    body = QuicTextUtils::HexDecode(FLAGS_body_hex);
  }

  // Construct a GET or POST request for supplied URL.
  SpdyHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.host();
  header_block[":path"] = url.path();

  // Append any additional headers supplied on the command line.
  for (QuicStringPiece sp : QuicTextUtils::Split(FLAGS_headers, ';')) {
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<QuicStringPiece> kv = QuicTextUtils::Split(sp, ':');
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }

  // Make sure to store the response, for later output.
  client.set_store_response(true);*/

  //added by blitzhong
  //2017-10-23
  char proxy_port[10] ="6789";

  int sfd, s;
  int efd;
  struct epoll_event event;
  struct epoll_event *events;
  net::QuicSimpleClient **head_client;

  sfd = create_and_bind (proxy_port);
  if (sfd == -1)
    abort ();

  s = make_socket_non_blocking (sfd);
  if (s == -1)
    abort ();

  s = listen (sfd, SOMAXCONN);
  if (s == -1)
    {
      perror ("listen");
      abort ();
    }

  efd = epoll_create1 (0);
  if (efd == -1)
    {
      perror ("epoll_create");
      abort ();
    }

  event.data.fd = sfd;
  event.events = EPOLLIN | EPOLLET;
  s = epoll_ctl (efd, EPOLL_CTL_ADD, sfd, &event);
  if (s == -1)
    {
      perror ("epoll_ctl");
      abort ();
    }

  /* Buffer where events are returned */
  events = (struct epoll_event *) calloc (MAXEVENTS, sizeof event);
  head_client = new net::QuicSimpleClient *[MAXEVENTS];
  memset(head_client, 0, MAXEVENTS * sizeof(net::QuicSimpleClient *));

  /* The event loop */
  while (1)
  {
        int n, i;

        n = epoll_wait (efd, events, MAXEVENTS, 1000);
        for (i = 0; i < n; i++)
        {
          if ((events[i].events & EPOLLERR) ||
                (events[i].events & EPOLLHUP) ||
                (!(events[i].events & EPOLLIN)))
          {
                /* An error has occured on this fd, or the socket is not
                   ready for reading (why were we notified then?) */
            fprintf (stderr, "epoll error\n");
            close (events[i].data.fd);
            continue;
          }

          else if (sfd == events[i].data.fd)
          {
                /* We have a notification on the listening socket, which
                   means one or more incoming connections. */
                while (1)
                {
                    struct sockaddr in_addr;
                    socklen_t in_len;
                    int infd;

                    in_len = sizeof in_addr;
                    infd = accept (sfd, &in_addr, &in_len);
                    if (infd == -1)
                    {
                        if ((errno == EAGAIN) ||
                            (errno == EWOULDBLOCK))
                        {
                          /* We have processed all incoming
                             connections. */
                          break;
                        }
                        else
                        {
                          perror ("accept");
                          break;
                        }
                    }
		printf("accept a new connection, fd=%d\n", infd);


  // Build the client, and try to connect.
  net::QuicServerId server_id(url.host(), url.EffectiveIntPort(),
                              net::PRIVACY_MODE_DISABLED);
  net::QuicVersionVector versions = net::AllSupportedVersions();
  if (FLAGS_quic_version != -1) {
    versions.clear();
    versions.push_back(static_cast<net::QuicVersion>(FLAGS_quic_version));
  }
  // For secure QUIC we need to verify the cert chain.
  std::unique_ptr<CertVerifier> cert_verifier(CertVerifier::CreateDefault());
  std::unique_ptr<TransportSecurityState> transport_security_state(
      new TransportSecurityState);
  std::unique_ptr<MultiLogCTVerifier> ct_verifier(new MultiLogCTVerifier());
  ct_verifier->AddLogs(net::ct::CreateLogVerifiersForKnownLogs());
  std::unique_ptr<CTPolicyEnforcer> ct_policy_enforcer(new CTPolicyEnforcer());
  std::unique_ptr<ProofVerifier> proof_verifier;
  if (line->HasSwitch("disable-certificate-verification")) {
    proof_verifier.reset(new FakeProofVerifier());
  } else {
    proof_verifier.reset(new ProofVerifierChromium(
        cert_verifier.get(), ct_policy_enforcer.get(),
        transport_security_state.get(), ct_verifier.get()));
  }

  net::QuicSimpleClient *client = new net::QuicSimpleClient(net::QuicSocketAddress(ip_addr, port), server_id,
                               versions, std::move(proof_verifier));
  client->set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : net::kDefaultMaxPacketSize);
  if (!client->Initialize()) {
    cerr << "Failed to initialize client." << endl;
    return 1;
  }
  if (!client->Connect()) {
    net::QuicErrorCode error = client->session()->error();
    if (FLAGS_version_mismatch_ok && error == net::QUIC_INVALID_VERSION) {
      cout << "Server talks QUIC, but none of the versions supported by "
           << "this client: " << QuicVersionVectorToString(versions) << endl;
      // Version mismatch is not deemed a failure.
      return 0;
    }
    cerr << "Failed to connect to " << host_port
         << ". Error: " << net::QuicErrorCodeToString(error) << endl;
    return 1;
  }
  cout << "Connected to " << host_port << endl;

  // Make sure to store the response, for later output.
  client->set_store_response(true);

  head_client[infd] = client;


                    /* Make the incoming socket non-blocking and add it to the
                       list of fds to monitor. */
                    s = make_socket_non_blocking (infd);
                    if (s == -1)
                      abort ();

                    event.data.fd = infd;
                    event.events = EPOLLIN | EPOLLET;
                    s = epoll_ctl (efd, EPOLL_CTL_ADD, infd, &event);
                    if (s == -1)
                    {
                        perror ("epoll_ctl");
                        abort ();
                    }
                  }

                  continue;
            }
            else
            {
                /* We have data on the fd waiting to be read. Read and
                   display it. We must read whatever data is available
                   completely, as we are running in edge-triggered mode
                   and won't get a notification again for the same
                   data. */
                int done = 0;

                while (1)
                {
                    ssize_t count;
                    char buf[8192];

                    count = read (events[i].data.fd, buf, sizeof(buf));
                    if (count == -1)
                    {
                        /* If errno == EAGAIN, that means we have read all
                           data. So go back to the main loop. */
                        if (errno != EAGAIN)
                        {
                            perror ("read");
                            done = 1;
                        }
                        break;
                    }
                    else if (count == 0)
                    {
                        /* End of file. The remote has closed the
                           connection. */
                        done = 1;
                        break;
                    }

  // Construct the string body from flags, if provided.
  string body = FLAGS_body;
  if (!FLAGS_body_hex.empty()) {
    DCHECK(FLAGS_body.empty()) << "Only set one of --body and --body_hex.";
    body = QuicTextUtils::HexDecode(FLAGS_body_hex);
  }

  // Construct a GET or POST request for supplied URL.
  SpdyHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.host();
  header_block[":path"] = url.path();

  // Append any additional headers supplied on the command line.
  for (QuicStringPiece sp : QuicTextUtils::Split(FLAGS_headers, ';')) {
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<QuicStringPiece> kv = QuicTextUtils::Split(sp, ':');
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }

                    body = buf;

                    // Send the request.

                    if(!head_client[events[i].data.fd]) 
                    {
                      fprintf(stderr, "error in loop");
                      break;
                    }
                    head_client[events[i].data.fd]->SetAddr(events[i].data.fd);
                    head_client[events[i].data.fd]->SendRequest(header_block, body, /*fin=*/true);
                    //client.SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);


                    //sleep(10);

                    // Print request and response details.
                    /*if (!FLAGS_quiet) {
                      cout << "Request:" << endl;
                      cout << "headers:" << header_block.DebugString();
                      if (!FLAGS_body_hex.empty()) {
                        // Print the user provided hex, rather than binary body.
                        cout << "body:\n"
                             << QuicTextUtils::HexDump(QuicTextUtils::HexDecode(FLAGS_body_hex))
                             << endl;
                      } else {
                        cout << "body: " << body << endl;
                      }
                      cout << endl;
                      cout << "Response:" << endl;
                      cout << "headers: " << client.latest_response_headers() << endl;
                      string response_body = client.latest_response_body();
                      
                      send(events[i].data.fd, response_body.c_str(),response_body.length(), 0);

                      if (!FLAGS_body_hex.empty()) {
                        // Assume response is binary data.
                        cout << "body:\n" << QuicTextUtils::HexDump(response_body) << endl;
                      } else {
                        cout << "body: " << response_body << endl;
                      }
                      cout << "trailers: " << client.latest_response_trailers() << endl;
                    }

                    size_t response_code = client.latest_response_code();
                    if (response_code >= 200 && response_code < 300) {
                      cout << "Request succeeded (" << response_code << ")." << endl;
                      //return 0;
                    } else if (response_code >= 300 && response_code < 400) {
                      if (FLAGS_redirect_is_success) {
                        cout << "Request succeeded (redirect " << response_code << ")." << endl;
                        return 0;
                      } else {
                        cout << "Request failed (redirect " << response_code << ")." << endl;
                        return 1;
                      }
                    } else {
                      cerr << "Request failed (" << response_code << ")." << endl;
                      return 1;
                    }*/

                    /* Write the buffer to standard output */
                    /*s = write (1, buf, count);
                    if (s == -1)
                    {
                        perror ("write");
                        abort ();
                    }*/
                }
                if (done)
                {
                    delete head_client[events[i].data.fd];
                    head_client[events[i].data.fd] = NULL;
                    printf ("Closed connection on descriptor %d\n",
                            events[i].data.fd);
                    /* Closing the descriptor will make epoll remove it
                       from the set of descriptors which are monitored. */
                    close (events[i].data.fd);
                }
            }
        }
        for (i = 0; i < MAXEVENTS; i++)
        {
            if(head_client[events[i].data.fd])
            {
              if (!head_client[events[i].data.fd]->WaitForEvents()) {
              }
            }
         }
    }

    for (auto i = 0; i < MAXEVENTS; i++)
    {
      if(head_client[events[i].data.fd])
        free(head_client[events[i].data.fd]);
    }
    free (events);
    close (sfd);

  return 0;
}
