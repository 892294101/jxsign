package jxsign

import (
	"fmt"
	"github.com/robertkrimen/otto"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unsafe"
)

var SignTool SignerSvc

func init() {
	SignTool = NewSigner()
}

type SignerSvc interface {
	GetSignString(params map[string]string) string
	GetSign(e string) string
}

type Signer struct {
	vm  *otto.Otto
	mux sync.Mutex
}

func NewSigner() *Signer {
	vm := otto.New()
	vm.Run(`
function o(e, t) {
            var n, i, o, a, r;
            return o = 2147483648 & e,
            a = 2147483648 & t,
            n = 1073741824 & e,
            i = 1073741824 & t,
            r = (1073741823 & e) + (1073741823 & t),
            n & i ? 2147483648 ^ r ^ o ^ a : n | i ? 1073741824 & r ? 3221225472 ^ r ^ o ^ a : 1073741824 ^ r ^ o ^ a : r ^ o ^ a
        }

function g(e) {
            var t, n, i = "", o = "";
            for (n = 0; n <= 3; n++)
                t = e >>> 8 * n & 255,
                o = "0" + t.toString(16),
                i += o.substr(o.length - 2, 2);
            return i
        }

function a(e, t, n) {
	return e & t | ~e & n
}

function r(e, t, n) {
	return e & n | t & ~n
}

function i(e, t) {
	return e << t | e >>> 32 - t
}

function c(e, t, n) {
	return e ^ t ^ n
}

function l(e, t, n) {
	return t ^ (e | ~n)
}
`)

	return &Signer{
		vm: vm,
	}
}

func (sgr *Signer) GetSignString(params map[string]string) string {
	signString := ""

	keys := make([]string, 0, len(params))
	for k, _ := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		signString += k + params[k]
	}
	signString += "048a9c4943398714b356a696503d2d36"
	return signString
}

// js << 操作
func jsLeft(a, i int) int {
	r := jsint32(jsBInt32(a) << (uint(i) % 32))
	if r >= 1<<31 {
		return r - 1<<32
	} else {
		return r
	}
}

// js >>> 操作
func jsPositiveRight(a, i int) int {
	r := jsint32(jsBInt32(a) >> (uint(i) % 32))
	return r
}

// js >> 操作
func jsRight(a, i int) int {
	r := jsint32(jsBInt32(a) >> (uint(i) % 32))
	if r >= 1<<31 {
		return r - 1<<32
	} else {
		return r
	}
}

// 转js int32
func jsint32(s int) int {
	ss := fmt.Sprintf("%08b", s)
	if len(ss) > 32 {
		kk, _ := strconv.ParseUint(ss[len(ss)-32:], 2, 32)
		return int(kk)
	} else {
		return s
	}
}

// (负数问题)转js 无符号int32
func jsBInt32(n int) int {
	var binStr string
	binStr = strconv.FormatUint(uint64(*(*uint64)(unsafe.Pointer(&n))), 2)
	if len(binStr) > 32 {
		binStr = binStr[len(binStr)-32:]
	}
	i, err := strconv.ParseUint(binStr, 2, 32)
	if err != nil {
		panic(err)
	}
	return int(i)
}

func arrayIndex(s []int, i int) int {
	if i >= len(s) {
		return 0
	} else {
		return s[i]
	}
}

func (sgr *Signer) oo(e, t int) int {
	sgr.mux.Lock()
	defer sgr.mux.Unlock()
	o, _ := sgr.vm.Call("o", nil, e, t)
	result, _ := o.ToInteger()
	return int(result)
}

func (sgr *Signer) bb(e string) string {
	ee := []rune(strings.Replace(e, "\x0d\x0a", "\n", -1))
	t := ""
	for n := 0; n < len(e); n++ {
		i := ee[n]
		if i < 128 {
			t += string(i)
		} else {
			if i > 127 && i < 2048 {
				t += strconv.Itoa(jsRight(int(i), 12) | 224)
				t += strconv.Itoa(63&int(i) | 128)
			} else {
				t += strconv.Itoa(jsRight(int(i), 12) | 224)
				t += strconv.Itoa(jsRight(int(i), 6)&63 | 128)
				t += strconv.Itoa(63&int(i) | 128)
			}
		}
	}
	return t
}

func (sgr *Signer) ggg(e int) string {
	sgr.mux.Lock()
	defer sgr.mux.Unlock()
	g, _ := sgr.vm.Call("g", nil, e)
	result, _ := g.ToString()
	return result
}

func (sgr *Signer) aaa(e, t, n int) int {
	sgr.mux.Lock()
	defer sgr.mux.Unlock()
	a, _ := sgr.vm.Call("a", nil, e, t, n)
	result, _ := a.ToInteger()
	return int(result)
}

func (sgr *Signer) rrr(e, t, n int) int {
	sgr.mux.Lock()
	defer sgr.mux.Unlock()
	r, _ := sgr.vm.Call("r", nil, e, t, n)
	result, _ := r.ToInteger()
	return int(result)
}

func (sgr *Signer) iii(e, t int) int {
	sgr.mux.Lock()
	defer sgr.mux.Unlock()
	i, _ := sgr.vm.Call("i", nil, e, t)
	result, _ := i.ToInteger()
	return int(result)
}

func (sgr *Signer) ccc(e, t, n int) int {
	sgr.mux.Lock()
	defer sgr.mux.Unlock()
	c, _ := sgr.vm.Call("c", nil, e, t, n)
	result, _ := c.ToInteger()
	return int(result)
}

func (sgr *Signer) lll(e, t, n int) int {
	sgr.mux.Lock()
	defer sgr.mux.Unlock()
	l, _ := sgr.vm.Call("l", nil, e, t, n)
	result, _ := l.ToInteger()
	return int(result)
	//return t ^ (e | ^n)
}

func (sgr *Signer) ss(e, t, n, r, c, l, s int) int {
	e = sgr.oo(e, sgr.oo(sgr.oo(sgr.aaa(t, n, r), c), s))
	return sgr.oo(sgr.iii(e, l), t)
}

func (sgr *Signer) dd(e, t, n, a, c, l, s int) int {
	e = sgr.oo(e, sgr.oo(sgr.oo(sgr.rrr(t, n, a), c), s))
	return sgr.oo(sgr.iii(e, l), t)
}

func (sgr *Signer) uu(e, t, n, a, r, l, s int) int {
	e = sgr.oo(e, sgr.oo(sgr.oo(sgr.ccc(t, n, a), r), s))
	return sgr.oo(sgr.iii(e, l), t)
}

func (sgr *Signer) ii(e, t, n, a, r, c, s int) int {
	e = sgr.oo(e, sgr.oo(sgr.oo(sgr.lll(t, n, a), r), s))
	return sgr.oo(sgr.iii(e, c), t)
}

func pp(e string) []int {
	var (
		t  int
		ee = []rune(e)
		n  = len(e)
		i  = n + 8
		o  = (i - i%64) / 64
		a  = 16 * (o + 1)
		r  = make([]int, a)
		c  = 0
		l  = 0
	)
	for l < n {
		t = (l - l%4) / 4
		c = l % 4 * 8
		r[t] = r[t] | jsLeft(int(ee[l]), c)
		l++
	}
	t = (l - l%4) / 4
	c = l % 4 * 8
	r[t] = r[t] | jsLeft(128, c)
	r[a-2] = jsLeft(n, 3)
	r[a-1] = jsPositiveRight(n, 29)
	return r
}

func (sgr *Signer) GetSign(e string) string {
	ee := sgr.bb(e)
	s := pp(ee)

	var (
		A, b, y, x int
		l          = 1732584193
		d          = 4023233417
		u          = 2562383102
		p          = 271733878
		i          = 7
		j          = 12
		k          = 17
		m          = 22
		E          = 5
		f          = 9
		g          = 14
		o          = 20
		I          = 4
		J          = 11
		K          = 16
		L          = 23
		O          = 6
		P          = 10
		Q          = 15
		R          = 21
	)
	for h := 0; h < countLen(s); h += 16 {
		A = l
		b = d
		y = u
		x = p
		l = sgr.ss(l, d, u, p, arrayIndex(s, h+0), i, 3614090360)
		p = sgr.ss(p, l, d, u, arrayIndex(s, h+1), j, 3905402710)
		u = sgr.ss(u, p, l, d, arrayIndex(s, h+2), k, 606105819)
		d = sgr.ss(d, u, p, l, arrayIndex(s, h+3), m, 3250441966)
		l = sgr.ss(l, d, u, p, arrayIndex(s, h+4), i, 4118548399)
		p = sgr.ss(p, l, d, u, arrayIndex(s, h+5), j, 1200080426)
		u = sgr.ss(u, p, l, d, arrayIndex(s, h+6), k, 2821735955)
		d = sgr.ss(d, u, p, l, arrayIndex(s, h+7), m, 4249261313)
		l = sgr.ss(l, d, u, p, arrayIndex(s, h+8), i, 1770035416)
		p = sgr.ss(p, l, d, u, arrayIndex(s, h+9), j, 2336552879)
		u = sgr.ss(u, p, l, d, arrayIndex(s, h+10), k, 4294925233)
		d = sgr.ss(d, u, p, l, arrayIndex(s, h+11), m, 2304563134)
		l = sgr.ss(l, d, u, p, arrayIndex(s, h+12), i, 1804603682)
		p = sgr.ss(p, l, d, u, arrayIndex(s, h+13), j, 4254626195)
		u = sgr.ss(u, p, l, d, arrayIndex(s, h+14), k, 2792965006)
		d = sgr.ss(d, u, p, l, arrayIndex(s, h+15), m, 1236535329)
		l = sgr.dd(l, d, u, p, arrayIndex(s, h+1), E, 4129170786)
		p = sgr.dd(p, l, d, u, arrayIndex(s, h+6), f, 3225465664)
		u = sgr.dd(u, p, l, d, arrayIndex(s, h+11), g, 643717713)
		d = sgr.dd(d, u, p, l, arrayIndex(s, h+0), o, 3921069994)
		l = sgr.dd(l, d, u, p, arrayIndex(s, h+5), E, 3593408605)
		p = sgr.dd(p, l, d, u, arrayIndex(s, h+10), f, 38016083)
		u = sgr.dd(u, p, l, d, arrayIndex(s, h+15), g, 3634488961)
		d = sgr.dd(d, u, p, l, arrayIndex(s, h+4), o, 3889429448)
		l = sgr.dd(l, d, u, p, arrayIndex(s, h+9), E, 568446438)
		p = sgr.dd(p, l, d, u, arrayIndex(s, h+14), f, 3275163606)
		u = sgr.dd(u, p, l, d, arrayIndex(s, h+3), g, 4107603335)
		d = sgr.dd(d, u, p, l, arrayIndex(s, h+8), o, 1163531501)
		l = sgr.dd(l, d, u, p, arrayIndex(s, h+13), E, 2850285829)
		p = sgr.dd(p, l, d, u, arrayIndex(s, h+2), f, 4243563512)
		u = sgr.dd(u, p, l, d, arrayIndex(s, h+7), g, 1735328473)
		d = sgr.dd(d, u, p, l, arrayIndex(s, h+12), o, 2368359562)
		l = sgr.uu(l, d, u, p, arrayIndex(s, h+5), I, 4294588738)
		p = sgr.uu(p, l, d, u, arrayIndex(s, h+8), J, 2272392833)
		u = sgr.uu(u, p, l, d, arrayIndex(s, h+11), K, 1839030562)
		d = sgr.uu(d, u, p, l, arrayIndex(s, h+14), L, 4259657740)
		l = sgr.uu(l, d, u, p, arrayIndex(s, h+1), I, 2763975236)
		p = sgr.uu(p, l, d, u, arrayIndex(s, h+4), J, 1272893353)
		u = sgr.uu(u, p, l, d, arrayIndex(s, h+7), K, 4139469664)
		d = sgr.uu(d, u, p, l, arrayIndex(s, h+10), L, 3200236656)
		l = sgr.uu(l, d, u, p, arrayIndex(s, h+13), I, 681279174)
		p = sgr.uu(p, l, d, u, arrayIndex(s, h+0), J, 3936430074)
		u = sgr.uu(u, p, l, d, arrayIndex(s, h+3), K, 3572445317)
		d = sgr.uu(d, u, p, l, arrayIndex(s, h+6), L, 76029189)
		l = sgr.uu(l, d, u, p, arrayIndex(s, h+9), I, 3654602809)
		p = sgr.uu(p, l, d, u, arrayIndex(s, h+12), J, 3873151461)
		u = sgr.uu(u, p, l, d, arrayIndex(s, h+15), K, 530742520)
		d = sgr.uu(d, u, p, l, arrayIndex(s, h+2), L, 3299628645)
		l = sgr.ii(l, d, u, p, arrayIndex(s, h+0), O, 4096336452)
		p = sgr.ii(p, l, d, u, arrayIndex(s, h+7), P, 1126891415)
		u = sgr.ii(u, p, l, d, arrayIndex(s, h+14), Q, 2878612391)
		d = sgr.ii(d, u, p, l, arrayIndex(s, h+5), R, 4237533241)
		l = sgr.ii(l, d, u, p, arrayIndex(s, h+12), O, 1700485571)
		p = sgr.ii(p, l, d, u, arrayIndex(s, h+3), P, 2399980690)
		u = sgr.ii(u, p, l, d, arrayIndex(s, h+10), Q, 4293915773)
		d = sgr.ii(d, u, p, l, arrayIndex(s, h+1), R, 2240044497)
		l = sgr.ii(l, d, u, p, arrayIndex(s, h+8), O, 1873313359)
		p = sgr.ii(p, l, d, u, arrayIndex(s, h+15), P, 4264355552)
		u = sgr.ii(u, p, l, d, arrayIndex(s, h+6), Q, 2734768916)
		d = sgr.ii(d, u, p, l, arrayIndex(s, h+13), R, 1309151649)
		l = sgr.ii(l, d, u, p, arrayIndex(s, h+4), O, 4149444226)
		p = sgr.ii(p, l, d, u, arrayIndex(s, h+11), P, 3174756917)
		u = sgr.ii(u, p, l, d, arrayIndex(s, h+2), Q, 718787259)
		d = sgr.ii(d, u, p, l, arrayIndex(s, h+9), R, 3951481745)
		l = sgr.oo(l, A)
		d = sgr.oo(d, b)
		u = sgr.oo(u, y)
		p = sgr.oo(p, x)
	}
	return strings.ToLower(sgr.ggg(l) + sgr.ggg(d) + sgr.ggg(u) + sgr.ggg(p))
}

// 按js的方式计算len
func countLen(s []int) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] != 0 {
			return i
		}
	}
	return 0
}
