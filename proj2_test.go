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

	_, err5 := InitUser("Roshan", "oskiii")
	if err5 == nil {
		t.Error("Duplicate username", err5)
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

	u1, err5 := InitUser("Ganesh", "securityIzFuN!!")
	if err5 != nil {
		t.Error("Failed to initialize user", err5)
		return
	}

	u2, err6 := InitUser("Neil", "I love working as a Walmart cashier!!")
	if err6 != nil {
		t.Error("Failed to initialize user", err6)
		return
	}

	accTok, err7 := u.ShareFile("file1", "Ganesh")
	if err7 != nil {
		t.Error("Failed to share file", err7)
		return
	}

	u1.ReceiveFile("file1", "Roshan", accTok)

	accTok2, err8 := u1.ShareFile("file1", "Neil")
	if err8 != nil {
		t.Error("Failed to share file", err8)
		return
	}

	u2.ReceiveFile("file1", "Ganesh", accTok2)

	v6 := []byte("Ganesh is appending this")
	err9 := u1.AppendFile("file1", v6)
	if err9 != nil {
		t.Error("Ganesh failed to append", err9)
		return
	}

	v7 := []byte("Neil is appending this")
	err10 := u2.AppendFile("file1", v7)
	if err10 != nil {
		t.Error("Neil failed to append", err10)
		return
	}

	v8 := []byte("This is a test" + "Appending this to my test file" + "Ganesh is appending this" + "Neil is appending this")
	
	v9, err11 := u1.LoadFile("file1")
	if err11 != nil {
		t.Error("Could not load file after appending", err11)
		return
	}

	if string(v8) != string(v9) {
		t.Error("Did not append contents correctly", err11)
		return 
	}
	
	v10, err12 := u2.LoadFile("file1")
	if err12 != nil {
		t.Error("Could not load file after appending", err12)
		return
	}

	if string(v8) != string(v10) {
		t.Error("Did not append contents correctly", err12)
		return 
	}

	v11, err13 := u.LoadFile("file1")
	if err13 != nil {
		t.Error("Could not load file after appending", err13)
		return
	}

	if string(v8) != string(v11) {
		t.Error("Did not append contents correctly", err13)
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
	//test evesdropper
	clear()
	roshan, _ := InitUser("roshan", "badpswd")
	ganesh, _ := InitUser("ganesh", "badpswd")
	eve, _ := InitUser("eve", "badpswd")

	roshan.StoreFile("checkevesdrop", []byte("can eve see this?"))
	token, basicshareerror := roshan.ShareFile("checkevesdrop", "ganesh")
	if basicshareerror != nil{
		t.Error("Unable to share", basicshareerror)
		return
	}

	_ = eve.ReceiveFile("evetriedtoload", "ganesh", token)
	evefiledata, evecannotsee := eve.LoadFile("evetriedtoload")
	if evecannotsee == nil{
		t.Error("Eve was able to access file")
		t.Error(string(evefiledata))
		return
	}
	_ = ganesh.ReceiveFile("ganeshtriedtoload", "roshan", token)
	ganeshfiledata, ganeshcansee := ganesh.LoadFile("ganeshtriedtoload")
	if ganeshcansee != nil{
		t.Error("Ganesh could not access file")
		t.Error(string(ganeshfiledata))
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

func TestMultipleUsers(t *testing.T) {
	clear()

	_, err := InitUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	_, err2 := InitUser("Ganesh", "securityIzFuN!!")
	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	roshanU1, err3 := GetUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err3 != nil {
		t.Error("Failed to get user", err3)
		return
	}

	roshanU2, err4 := GetUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err4 != nil {
		t.Error("Failed to get user", err4)
		return
	}

	ganeshU1, err5 := GetUser("Ganesh", "securityIzFuN!!")
	if err5 != nil {
		t.Error("Failed to get user", err5)
		return
	}

	ganeshU2, err6 := GetUser("Ganesh", "securityIzFuN!!")
	if err2 != nil {
		t.Error("Failed to get user", err6)
		return
	}

	v := []byte("This is a test")
	roshanU1.StoreFile("file1", v)

	accTok, err7 := roshanU1.ShareFile("file1", "Ganesh")
	if err7 != nil {
		t.Error("Failed to share file", err7)
		return
	}

	err10 := ganeshU1.ReceiveFile("file1", "Roshan", accTok)
	if err10 != nil {
		t.Error("Failed to receive file", err10)
		return
	}

	_, err11 := ganeshU1.LoadFile("file1")
	if err11 != nil {
		t.Error("Failed to download file", err11)
		return
	}

	_, err12 := ganeshU2.LoadFile("file1")
	if err12 != nil {
		t.Error("Failed to download file", err12)
		return
	}

	_, err13:= roshanU1.LoadFile("file1")
	if err13 != nil {
		t.Error("Failed to download file", err13)
		return
	}

	_, err14:= roshanU2.LoadFile("file1")
	if err14 != nil {
		t.Error("Failed to download file", err14)
		return
	}

	_, err15 := InitUser("Neil", "I love working as a Walmart cashier!!")
	if err15 != nil {
		t.Error("Failed to initialize user", err15)
		return
	}

	neilU1, err16 := GetUser("Neil", "I love working as a Walmart cashier!!")
	if err16 != nil {
		t.Error("Failed to get user", err16)
		return
	}

	neilU2, err17 := GetUser("Neil", "I love working as a Walmart cashier!!")
	if err17 != nil {
		t.Error("Failed to get user", err17)
		return
	}

	accTok2, err18 := ganeshU1.ShareFile("file1", "Neil")
	if err18 != nil {
		t.Error("Failed to share file", err18)
		return
	}

	err19 := neilU1.ReceiveFile("file2", "Ganesh", accTok2)
	if err19 != nil {
		t.Error("Failed to receive file", err19)
		return
	}

	_, err20 := neilU1.LoadFile("file2")
	if err20 != nil {
		t.Error("Failed to download file", err20)
		return
	}

	_, err21 := neilU2.LoadFile("file2")
	if err21 != nil {
		t.Error("Failed to download file", err21)
		return
	}

	err22 := ganeshU2.RevokeFile("file1", "Roshan")
	if err22 == nil {
		t.Error("Tried to revoke access from creator", err22)
		return
	}

	err23 := neilU2.RevokeFile("file2", "Ganesh")
	if err23 == nil {
		t.Error("Tried to revoke access when user was not creator", err23)
		return
	}

	err24 := neilU1.RevokeFile("file2", "Ganesh")
	if err24 == nil {
		t.Error("Tried to revoke access when user was not creator", err24)
		return
	}

	err25 := roshanU2.RevokeFile("file1", "Ganesh")
	if err25 != nil {
		t.Error("Failed to revoke access", err25)
		return
	}
	
	_, err26 := neilU1.LoadFile("file2")
	if err26 == nil {
		t.Error("Downloaded file after access was revoked", err26)
		return
	}

	_, err27 := neilU2.LoadFile("file2")
	if err27 == nil {
		t.Error("Downloaded file after access was revoked", err27)
		return
	}

	_, err28 := ganeshU1.LoadFile("file1")
	if err28 == nil {
		t.Error("Downloaded file after access was revoked", err28)
		return
	}

	_, err29 := ganeshU2.LoadFile("file1")
	if err29 == nil {
		t.Error("Downloaded file after access was revoked", err29)
		return
	}



}

func TestRevokeFile(t *testing.T) {
	clear()

	roshan, err := InitUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}

	ganesh, err1 := InitUser("Ganesh", "securityIzFuN!!")
	if err1 != nil {
		t.Error("Failed to initialize user", err1)
		return
	}

	neil, err2 := InitUser("Neil", "I love working as a Walmart cashier!!")
	if err2 != nil {
		t.Error("Failed to initialize user", err2)
		return
	}

	v := []byte("This is a test")
	roshan.StoreFile("file1", v)

	accTok, err3 := roshan.ShareFile("file1", "Ganesh")
	if err3 != nil {
		t.Error("Failed to share file", err3)
		return
	}

	err4 := ganesh.ReceiveFile("file1", "Roshan", accTok)
	if err4 != nil {
		t.Error("Failed to receive file", err4)
		return
	}

	accTok2, err5 := ganesh.ShareFile("file1", "Neil")
	if err5 != nil {
		t.Error("Failed to share file", err5)
		return
	}

	err6 := neil.ReceiveFile("file1", "Ganesh", accTok2)
	if err6 != nil {
		t.Error("Failed to receive file", err6)
		return
	}

	_, err7 := ganesh.LoadFile("file1")
	if err7 != nil {
		t.Error("Failed to download file", err7)
		return
	}

	_, err8:= neil.LoadFile("file1")
	if err8 != nil {
		t.Error("Failed to download file", err8)
		return
	}

	err9 := roshan.RevokeFile("file1", "Ganesh")
	if err9 != nil {
		t.Error("Failed to revoke access", err9)
		return
	}

	filedata, err10 := ganesh.LoadFile("file1")
	if err10 == nil {
		t.Error("Downloaded file after access was revoked", filedata)
		//return
	}

	_, err11 := neil.LoadFile("file1")
	if err11 == nil {
		t.Error("Downloaded file after access (of user who shared it with them) was revoked", err11)
		return
	}

	err12 := ganesh.RevokeFile("file1", "Roshan")
	if err12 == nil {
		t.Error("Tried to revoke access from creator", err12)
		return
	}

}

/*
func TestFileDataIntegrity(t *testing.T) {
	clear()

	var file File

	u, err := InitUser("Roshan", "mEdiCineIzMyPaSSIon")
	if err != nil {
		t.Error("Failed to initialize user", err)
	return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)

	hashedFileID := userlib.Hash([]byte("file1" + "Roshan"))
	fileUUID, _ := uuid.FromBytes([]byte(hashedFileID[:16]))

	filestruct, _ := userlib.DatastoreGet(fileUUID)
	json.Unmarshal(filestruct, &file)

	v2 := []byte("Ganesh hacked the file!!")

	file.FileData = v2

	hackedFile, _ := json.Marshal(file)
	userlib.DatastoreSet(fileUUID, hackedFile)
	
	
	_, err2 := u.LoadFile("file1")
	if err2 == nil {
		t.Error("Roshan didn't notice the filecontents were hacked!!", err2)
		return
	}

}

*/