package main

import (
	"github.com/1cloud-cn/alioss"
	"fmt"
	"time"
)

//a.tar.gz=>3D051400A0BB438D93415C67AFCBC0C4

func main() {
	t1 := time.Now().UnixNano()
	client := alioss.NewClient("DaNBIyYNMdOUykUM", "7FQfP7lhlFX74EdiEclDnPE2jU5qpK")
	bucket := alioss.NewBucket("nvgod-head", alioss.REGION_HANGZHOU_INTERNAL, client)
//	uploadId, error := bucket.InitiateMultipartUpload("a.tar.gz", nil)
////	error := bucket.Put("a.txt", bytes.NewReader([]byte("abc")), make(map[string]string, 0))
//	if error != nil {
//		fmt.Println(error)
//	} else {
//		fmt.Println(uploadId)
//	}
//	b, error := ioutil.ReadFile("j:\\mcdata_20141222.tar.gz")
//	etag,error := bucket.UploadPart("a.tar.gz", "3D051400A0BB438D93415C67AFCBC0C4", 1, b)
	error := bucket.PutLargeFile("010EditorWin64Installer60.exe", "f:\\010EditorWin64Installer60.exe",  nil)
	if error != nil {
		fmt.Println(error)
	}
	t2 := time.Now().UnixNano()
	fmt.Println(t2 - t1)
//	fmt.Println(etag)
}
