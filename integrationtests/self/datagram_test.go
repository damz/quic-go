package self_test

import (
	"context"
	"fmt"
	mrand "math/rand"
	"net"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	quicproxy "github.com/lucas-clemente/quic-go/integrationtests/tools/proxy"
	"github.com/lucas-clemente/quic-go/internal/protocol"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Datagram test", func() {
	for _, v := range protocol.SupportedVersions {
		version := v

		Context(fmt.Sprintf("with QUIC version %s", version), func() {
			const num = 100

			var (
				proxy                  *quicproxy.QuicProxy
				serverConn, clientConn *net.UDPConn
				dropped                int32
			)

			startServerAndProxy := func() {
				addr, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				serverConn, err = net.ListenUDP("udp", addr)
				Expect(err).ToNot(HaveOccurred())
				ln, err := quic.Listen(
					serverConn,
					getTLSConfig(),
					&quic.Config{
						MaxDatagramFrameSize: 64 << 10,
						Versions:             []protocol.VersionNumber{version},
					},
				)
				Expect(err).ToNot(HaveOccurred())
				go func() {
					defer GinkgoRecover()
					sess, err := ln.Accept(context.Background())
					Expect(err).ToNot(HaveOccurred())

					var wg sync.WaitGroup
					wg.Add(num)
					for i := 0; i < num; i++ {
						go func(i int) {
							defer GinkgoRecover()
							defer wg.Done()
							Expect(sess.SendDatagram([]byte(fmt.Sprintf("%d", i)))).To(Succeed())
						}(i)
					}
					wg.Wait()
				}()
				serverPort := ln.Addr().(*net.UDPAddr).Port
				proxy, err = quicproxy.NewQuicProxy("localhost:0", &quicproxy.Opts{
					RemoteAddr: fmt.Sprintf("localhost:%d", serverPort),
					// drop 10% of Short Header packets sent from the server
					DropPacket: func(dir quicproxy.Direction, packet []byte) bool {
						// return false
						if dir == quicproxy.DirectionIncoming {
							return false
						}
						// don't drop Long Header packets
						if packet[0]&0x80 == 1 {
							return false
						}
						drop := mrand.Int()%10 == 0
						if drop {
							atomic.AddInt32(&dropped, 1)
						}
						return drop
					},
				})
				Expect(err).ToNot(HaveOccurred())
			}

			BeforeEach(func() {
				addr, err := net.ResolveUDPAddr("udp", "localhost:0")
				Expect(err).ToNot(HaveOccurred())
				clientConn, err = net.ListenUDP("udp", addr)
				Expect(err).ToNot(HaveOccurred())
			})

			AfterEach(func() {
				Expect(proxy.Close()).To(Succeed())
			})

			It("sends datagrams", func() {
				startServerAndProxy()
				raddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("localhost:%d", proxy.LocalPort()))
				Expect(err).ToNot(HaveOccurred())

				ctx, cancelFn := context.WithTimeout(context.Background(), 1*time.Second)
				defer cancelFn()

				sess, err := quic.DialContext(
					ctx,
					clientConn,
					raddr,
					fmt.Sprintf("localhost:%d", proxy.LocalPort()),
					getTLSClientConfig(),
					&quic.Config{
						MaxDatagramFrameSize: 64 << 10,
						Versions:             []protocol.VersionNumber{version},
					},
				)
				Expect(err).ToNot(HaveOccurred())

				go func() {
					<-ctx.Done()
					sess.CloseWithError(0, ctx.Err().Error())
				}()

				var counter int
				for {
					data := make([]byte, 64<<10)
					_, err := sess.ReceiveDatagram(data)
					if err != nil {
						break
					}
					counter++
				}

				fmt.Fprintf(GinkgoWriter, "Dropped %d packets.", atomic.LoadInt32(&dropped))
				Expect(counter).To(And(
					BeNumerically(">", num*9/10),
					BeNumerically("<", num),
				))
			})
		})
	}
})
