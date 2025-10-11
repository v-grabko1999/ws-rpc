package wsrpc

import (
	"strings"
	"sync"
)

// --- ДОДАТИ: права доступу до RPC-функцій ---

// PermissionMode визначає режим перевірки прав.
type PermissionMode int

const (
	// PermissionDenyList — дозволено всі функції, КРІМ тих, що в списку.
	PermissionDenyList PermissionMode = iota

	// PermissionAllowList — заборонено всі функції, ОКРІМ тих, що в списку.
	PermissionAllowList
)

// Permission описує правила доступу для даного Endpoint.
// List — це множина імен RPC-функцій у форматі "Service.Method".
type Permission struct {
	mu   sync.RWMutex
	Mode PermissionMode
	List map[string]bool
}

// isAllowed перевіряє, чи можна викликати fn за поточним режимом та списком.
// Підтримує два рівні специфічності:
//  1. Точне співпадіння "Service.Method"
//  2. Правило на рівні сервісу "Service" (без крапки)
//
// Пріоритет: більш специфічне правило (Service.Method) переважає над правилом сервісу.
func (p *Permission) isAllowed(fn string) bool {
	if p == nil {
		// Немає політики — все дозволено.
		return true
	}

	p.mu.RLock()
	defer p.mu.RUnlock()

	// Визначаємо назву сервісу (префікс до крапки).
	var service string
	if i := strings.IndexByte(fn, '.'); i > 0 && i < len(fn)-1 {
		service = fn[:i]
	} else {
		// Якщо формат не "Service.Method", трактуємо як назву сервісу.
		service = fn
	}

	inExact := p.List != nil && p.List[fn]        // правило для конкретного методу
	inService := p.List != nil && p.List[service] // правило для всього сервісу

	switch p.Mode {
	case PermissionAllowList:
		// Дозволено лише те, що явно додано в список:
		// або конкретний метод, або весь сервіс.
		return inExact || inService

	case PermissionDenyList:
		// Дозволено все, що НЕ присутнє в списку ані як метод, ані як сервіс.
		return !(inExact || inService)

	default:
		return false
	}
}

// --- Зручні методи керування політикою ---

func (p *Permission) SetMode(m PermissionMode) {
	p.mu.Lock()
	p.Mode = m
	p.mu.Unlock()
}

func (p *Permission) Set(list map[string]bool, mode PermissionMode) {
	p.mu.Lock()
	p.Mode = mode
	p.List = make(map[string]bool, len(list))
	for k, v := range list {
		if v {
			p.List[k] = true
		}
	}
	p.mu.Unlock()
}

func (p *Permission) Allow(fns ...string) {
	p.mu.Lock()
	if p.List == nil {
		p.List = make(map[string]bool)
	}
	for _, fn := range fns {
		p.List[fn] = true
	}
	p.mu.Unlock()
}

func (p *Permission) Deny(fns ...string) {
	p.mu.Lock()
	if p.List == nil {
		p.List = make(map[string]bool)
	}
	for _, fn := range fns {
		p.List[fn] = true
	}
	p.mu.Unlock()
}

// Зручно очищати список (наприклад, перед застосуванням нової політики).
func (p *Permission) ResetList() {
	p.mu.Lock()
	p.List = make(map[string]bool)
	p.mu.Unlock()
}
