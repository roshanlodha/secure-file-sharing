package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.


//notes:
// 1) check invalid usernames

import (
	"testing"
	"reflect"
	"github.com/cs161-staff/userlib"
	_ "encoding/json"
	_ "encoding/hex"
	_ "github.com/google/uuid"
	_ "strings"
	_ "errors"
	_ "strconv"
)


func clear() {
	// Wipes the storage so one test does not affect another
	userlib.DatastoreClear()
	userlib.KeystoreClear()
}


func TestInit(t *testing.T) {
	clear()
	t.Log("Initialization test")

	// You can set this to false!
	userlib.SetDebugStatus(true)

	u, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	t.Log("Got user", u)
	// If you want to comment the line above,
	// write _ = u here to make the compiler happy
	// You probably want many more tests here.
}


func TestStorage(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Downloaded file is not the same", v, v2)
		return
	}
}


func TestInvalidFile(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := u.LoadFile("this file does not exist")
	if err2 == nil {
		t.Error("Downloaded a ninexistent file", err2)
		return
	}
}


func TestShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err2 := InitUser("bob", "foobar")
	if err2 != nil {
		t.Error("Failed to initialize bob", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	
	var v2 []byte
	var magic_string string

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("file1", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("file2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("file2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

}


func TestGetUser(t *testing.T) {
	clear()

	_, err := InitUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := GetUser("Roshan", "jk I hate medicine")
	if err2 == nil {
		t.Error("Accessed user with wrong password", err2)
		return
	}

	_, err3 := GetUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err3 != nil {
		t.Error("Could not access user with correct password", err3)
		return
	}

	_, err4 := GetUser("Ganesh", "mEdiCineIzMyPaSSIon")
	if err4 == nil {
		t.Error("Accessed user that does not exist", err4)
		return
	}

}


func TestStoreLoadFile(t *testing.T) {
	clear()

	u, err := InitUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)


	v2, err2 := u.LoadFile("file1")
	if err2 != nil {
		t.Error("Failed to download the file from Roshan", err2)
		return
	}

	if string(v) != string(v2) {
		t.Error("Filecontents do not match", err2)
		return
	}

	v3 := []byte("This is a test of overriding file contents")
	u.StoreFile("file1", v3)

	v4, err4 := u.LoadFile("file1")
	if string(v4) == string(v2) {
		t.Error("File contents not overwritten", err4)
		return
	}

	_, err5 := u.LoadFile("file2")
	if err5 == nil {
		t.Error("Downloaded a file that does not exist", err5)
		return
	}

}


func TestAppendFile(t *testing.T) {
	clear()

	u, err := InitUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)


	v1 := []byte("Appending this to my test file")
	err2 := u.AppendFile("file1", v1)
	if err2 != nil {
		t.Error("Failed to append to the file", err2)
		return
	}

	err3 := u.AppendFile("file2", v1)
	if err3 == nil {
		t.Error("Appended to a file that does not exist", err3)
		return
	}

	v2, err4 := u.LoadFile("file1")
	if err4 != nil {
		t.Error("Could not load file after appending", err4)
		return
	}

	v3 := []byte("This is a test" + "Appending this to my test file")
	if string(v3) != string(v2) {
		t.Error("Did not append contents correctly", err4)
		return 
	}


}



func TestShareFile(t *testing.T) {
	clear()

	u, err := InitUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err1 := InitUser("Ganesh", "securityIzFuN!!")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	_, err2 := u.ShareFile("file1", "Ganesh")
	if err2 != nil {
		t.Error("Failed to share file", err2)
		return
	}

	_, err3 := u.ShareFile("file1", "Obama")
	if err3 == nil {
		t.Error("Shared file with user that does not exist", err3)
		return
	}

	_, err4 := u.ShareFile("file2", "Ganesh")
	if err4 == nil {
		t.Error("Shared file that does not exist", err4)
		return
	}

	_, err5 := u.ShareFile("file2", "Obama")
	if err4 == nil {
		t.Error("Shared file that does not exist with user that does not exist", err5)
		return
	}

}


func TestReceiveFile(t *testing.T) {
	clear()

	u, err := InitUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u1, err1 := InitUser("Ganesh", "securityIzFuN!!")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	accTok, err2 := u.ShareFile("file1", "Ganesh")
	if err2 != nil {
		t.Error("Failed to share file", err2)
		return
	}

	err3 := u1.ReceiveFile("file1", "Roshan", accTok)
	if err3 != nil {
		t.Error("Failed to receive file", err3)
		return
	}

	err4 := u1.ReceiveFile("file1", "Roshan", accTok)
	if err4 == nil {
		t.Error("Shared a file that was already shared with user", err4)
		return
	}

	_, err5 := u1.LoadFile("file1")
	if err5 != nil {
		t.Error("Failed to download the file from Roshan", err5)
		return
	}

	v6 := []byte("Appending this")
	err6 := u1.AppendFile("file1", v6)
	if err6 != nil {
		t.Error("Failed to append to the file", err6)
		return
	}

	u2, err7 := InitUser("Obama", "democracy!!")
	if err7 != nil {
		t.Error("Failed to initialize user", err7)
		return
	}

	accTok2, err8 := u1.ShareFile("file1", "Obama")
	if err8 != nil {
		t.Error("Failed to share file", err8)
		return
	}

	err9 := u2.ReceiveFile("file1", "Ganesh", accTok2)
	if err9 != nil {
		t.Error("Unable to receive file", err9)
		return
	}

	_, err10 := u2.LoadFile("file1")
	if err10 != nil {
		t.Error("Failed to download the file from Ganesh", err10)
		return
	}

}

func TestRevokeFile(t *testing.T) {
	clear()

	u, err := InitUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	u1, err1 := InitUser("Ganesh", "securityIzFuN!!")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}

	u2, err2 := InitUser("Neil", "I love working as a Walmart cashier!!")
	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	accTok, err3 := u.ShareFile("file1", "Ganesh")
	if err3 != nil {
		t.Error("Failed to share file", err3)
		return
	}

	err4 := u1.ReceiveFile("file1", "Roshan", accTok)
	if err4 != nil {
		t.Error("Failed to receive file", err4)
		return
	}

	accTok2, err5 := u1.ShareFile("file1", "Neil")
	if err5 != nil {
		t.Error("Failed to share file", err5)
		return
	}

	err6 := u2.ReceiveFile("file1", "Ganesh", accTok2)
	if err6 != nil {
		t.Error("Failed to receive file", err6)
		return
	}

	_, err7 := u1.LoadFile("file1")
	if err7 != nil {
		t.Error("Failed to download file", err7)
		return
	}

	_, err8:= u2.LoadFile("file1")
	if err8 != nil {
		t.Error("Failed to download file", err8)
		return
	}

	err9 := u.RevokeFile("file1", "Ganesh")
	if err9 != nil {
		t.Error("Failed to revoke access", err9)
		return
	}

	_, err10 := u1.LoadFile("file1")
	if err10 == nil {
		t.Error("Downloaded file after access was revoked", err10)
		return
	}

	_, err11 := u2.LoadFile("file1")
	if err11 == nil {
		t.Error("Downloaded file after access (of user who shared it with them) was revoked", err11)
		return
	}


}