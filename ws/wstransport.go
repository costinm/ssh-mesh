package ws

import (
	"github.com/gorilla/websocket"
	"net/http"
)

func Server(w http.Response, r *http.Request) {
	u := websocket.Upgrader{}
}

// "golang.org/x/net/websocket" - not supported. Dial only text frames.
//
//func Server() http.Handler {
//	wsmsg := &ws.Server{
//		Config:    ws.Config{},
//		Handshake: nil,
//		Handler: func(conn *ws.Conn) {
//			//h2ctx := auth.AuthContext(conn.Request().Context())
//			//websocketStream(conn)
//		},
//	}
//	return wsmsg
//	//mux.Handle("/ws", wsmsg)
//}
//
//func Client(dest string) (*ws.Conn, error) {
//	wsc, err := ws.NewConfig(dest, dest)
//
//	//wsc.Header.Add("Authorization", a.VAPIDToken(dest))
//
//	wsc.TlsConfig = &tls.Config{
//		InsecureSkipVerify: true,
//	}
//
//	ws, err := ws.DialConfig(wsc)
//	if err != nil {
//		return nil, err
//	}
//
//	return ws, err
//}
