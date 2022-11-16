package MongoDB

import (
	"fmt"
	"github.com/JodeZer/mgop"
	"gopkg.in/mgo.v2/bson"
	"sync"
)

const connection = `mongodb://admin:JSDBuoydfo76Ykmn3DFo3R@192.168.1.203:27017/admin`

func main() {
	p, err := mgop.DialStrongPool(connection, 5)
	if err != nil {
		fmt.Printf("err !!%s", err)
		return
	}
	sp := sync.WaitGroup{}
	for i := 0; i < 1000; i++ {
		sp.Add(1)
		go func() {
			sp.Add(1)
			s := p.AcquireSession()
			defer s.Release()
			s.DB("quickpay").C("pt").Insert(bson.M{"iid": i})
			sp.Done()
		}()
		sp.Done()
	}
	sp.Wait()
}
func Foo() {
	p, _ := mgop.DialStrongPool("127.0.0.1:27017", 5)
	session := p.AcquireSession()
	defer session.Release()
	session.DB("test").C("test").Insert(bson.M{"id": 1})
}
