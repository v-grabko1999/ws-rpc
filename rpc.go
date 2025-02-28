package wsrpc

import "encoding/json"

// JSON-RPC запрос
type RPCRequest struct {
	JsonRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      *int        `json:"id,omitempty"`
}

// JSON-RPC ответ
type RPCResponse struct {
	JsonRPC string      `json:"jsonrpc"`
	Result  interface{} `json:"result,omitempty"`
	Error   *RPCError   `json:"error,omitempty"`
	ID      *int        `json:"id,omitempty"`
}

// JSON-RPC ошибка
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Функция для кодирования JSON-RPC ответа
func EncodeRPCResponse(id *int, result interface{}, rpcErr *RPCError) ([]byte, error) {
	response := RPCResponse{
		JsonRPC: "2.0",
		Result:  result,
		Error:   rpcErr,
		ID:      id,
	}
	return json.Marshal(response)
}
