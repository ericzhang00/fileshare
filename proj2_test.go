package proj2

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (
	_ "encoding/hex"
	_ "encoding/json"
	_ "errors"
	"github.com/cs161-staff/userlib"
	_ "github.com/google/uuid"
	"reflect"
	_ "strconv"
	_ "strings"
	"testing"
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
	userlib.SetDebugStatus(false)

	_, err := InitUser("alice", "fubar")
	if err != nil {
		// t.Error says the test fails
		t.Error("Failed to initialize user", err)
		return
	}
	// t.Log() only produces output if you run with "go test -v"
	//t.Log("Got user", u)

	_, err = GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get existing user", err)
	}
	//t.Log("Got user", u2)

	u3, err := GetUser("alice", "wrongpassword")
	if err == nil && u3 != nil {
		t.Error("Wrong password should return an error")
	}

	_, err = InitUser("", "papapapa")
	if err != nil {
		t.Error("Username empty", err)
		return
	}
	_, err = InitUser("uhhh", "")
	if err != nil {
		t.Error("Password empty", err)
		return
	}

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

	u.StoreFile("file2", v)
	v3, err3 := u.LoadFile("file2")
	if err3 != nil {
		t.Error("Failed to upload and download multiple files", err3)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Second downloaded file is not the same", v, v3)
		return
	}

	v4, err4 := u.LoadFile("file1")
	if err4 != nil {
		t.Error("Uploading subsequent files prevents downloading original", err4)
		return
	}
	if !reflect.DeepEqual(v, v4) {
		t.Error("Uploading subsequent files tampers with original", v, v4)
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
		t.Error("Downloaded a nonexistent file", err2)
		return
	}

	v := []byte("This is a test")
	u.StoreFile("file1", v)
	_, err3 := u.LoadFile("this file also does not exist")
	if err3 == nil {
		t.Error("Downloaded a nonexistent file from nonempty FileStore", err3)
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
	u3, err3 := InitUser("charles", "foooobar")
	if err3 != nil {
		t.Error("Failed to initialize charles", err2)
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

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Sharing file removed alice's access", err)
		return
	}

	magic_string, err = u2.ShareFile("file2", "charles")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	if !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	u.StoreFile("newfile", v)
	v, err = u.LoadFile("newfile")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("newfile", "bob")
	if err != nil {
		t.Error("Failed to share multiple files", err)
		return
	}
	err = u2.ReceiveFile("newfile2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive multiple files", err)
		return
	}

	v2, err = u2.LoadFile("newfile2")
	if err != nil {
		t.Error("Failed to download multiple files after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same after already sharing", v, v2)
		return
	}

	err = u3.ReceiveFile("newfile3", "alice", magic_string)
	if err == nil {
		t.Error("Received with unauthorized permissions", err)
		return
	}
	err = u2.ReceiveFile("newfile4", "alice", "randomstring")
	if err == nil {
		t.Error("Received with unauthorized permission string", err)
		return
	}
	err = u2.ReceiveFile("newfile5", "someone else", magic_string)
	if err == nil {
		t.Error("Received from wrong user", err)
		return
	}

	_, err = u.ShareFile("file1", "nonexistent user")
	if err == nil {
		t.Error("Shared to nonexistent user", err)
		return
	}


	_, err = u.ShareFile("nonexistent file", "charles")
	if err == nil {
		t.Error("Shared nonexistent file", err)
		return
	}



	u.StoreFile("other", v)
	v, err = u.LoadFile("other")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("other", "bob")
	if err != nil {
		t.Error("Failed to share file with bob", err)
		return
	}
	err = u2.ReceiveFile("", "alice", magic_string)
	if err == nil {
		t.Error("File cannot be empty string name", err)
		return
	}

}

func TestUser_RevokeFile(t *testing.T) {
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
	u3, err3 := InitUser("charles", "foooobar")
	if err3 != nil {
		t.Error("Failed to initialize charles", err2)
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

	magic_string, err = u2.ShareFile("file2", "charles")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v3, err := u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	err = u.RevokeFile("file1", "bob")
	if err != nil {
		t.Error("Revoke failed", err)
		return
	}
	v2, err = u2.LoadFile("file2")
	if err == nil {
		t.Error("Failed to revoke access after sharing", err)
		return
	}
	v3, err = u3.LoadFile("file3")
	if err == nil {
		t.Error("Failed to revoke access after sharing", err)
		return
	}
	_, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Revoking removed access for owner as well", err)
		return
	}


	u.StoreFile("newfile", v)
	v, err = u.LoadFile("newfile")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("newfile", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("newfile2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("newfile2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	magic_string, err = u.ShareFile("newfile", "charles")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = u3.ReceiveFile("newfile3", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v3, err = u3.LoadFile("newfile3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file is not the same", v, v3)
		return
	}

	err = u.RevokeFile("newfile", "bob")
	if err != nil {
		t.Error("Revoke failed", err)
		return
	}
	v2, err = u2.LoadFile("newfile2")
	if err == nil {
		t.Error("Failed to revoke access after sharing", err)
		return
	}
	v3, err = u3.LoadFile("newfile3")
	if err != nil {
		t.Error("Revoking from one 'child' revokes from all", err)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file is not the same after revoking elsewhere", v, v3)
		return
	}



	u.StoreFile("brandnewfile", v)
	v, err = u.LoadFile("brandnewfile")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}

	magic_string, err = u.ShareFile("brandnewfile", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("brandnewfile2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	v2, err = u2.LoadFile("brandnewfile2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}

	magic_string, err = u2.ShareFile("brandnewfile2", "charles")
	if err != nil {
		t.Error("Failed to share the file", err)
		return
	}
	err = u3.ReceiveFile("brandnewfile3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v3, err = u3.LoadFile("brandnewfile3")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v2, v3) {
		t.Error("Shared file is not the same", v2, v3)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Shared file is not the same", v, v3)
		return
	}

	err = u.RevokeFile("brandnewfile", "charles")
	if err == nil {
		t.Error("Revoked access from nondirect child", err)
	}
	v3, err = u3.LoadFile("brandnewfile3")
	if err != nil {
		t.Error("Access revoked from nondirect parent", err)
		return
	}
	v, err = u.LoadFile("brandnewfile")
	if err != nil {
		t.Error("Revoking removes access from owner as well", err)
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same after revoking elsewhere", v, v2)
		return
	}


	u.StoreFile("anothernewfile", v)
	v, err = u.LoadFile("anothernewfile")
	if err != nil {
		t.Error("Failed to download the file from alice", err)
		return
	}
	magic_string, err = u.ShareFile("anothernewfile", "bob")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u2.ReceiveFile("anothernewfile2", "alice", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v2, err = u2.LoadFile("anothernewfile2")
	if err != nil {
		t.Error("Failed to download the file after sharing", err)
		return
	}
	if !reflect.DeepEqual(v, v2) {
		t.Error("Shared file is not the same", v, v2)
		return
	}
	err = u.RevokeFile("anothernewfile", "bob")
	if err != nil {
		t.Error("Revoke failed", err)
		return
	}
	v2, err = u2.LoadFile("anothernewfile2")
	if err == nil {
		t.Error("File still downloaded after being revoked", err)
		return
	}

	//Can revoked file still be shareable????

	magic_string, err = u2.ShareFile("anothernewfile2", "charles")
	// if err == nil {
	// 	t.Error("File still shareable after being revoked", err)
	// 	return
	// }
	err = u3.ReceiveFile("anothernewfile3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	v3, err = u3.LoadFile("anothernewfile3")
	if err == nil {
		t.Error("charles can load file shared by someone without access", err)
		return
	}

	//???????????????

	text := []byte("some text idk")
	err = u2.AppendFile("anothernewfile2", text)
	if err == nil {
		t.Error("File still appendable after being revoked, err")
		return
	}



	err = u.RevokeFile("newfile", "nonexistent user")
	if err == nil {
		t.Error("Revoked from nonexistent user", err)
		return
	}

	err = u.RevokeFile("nonexistent file", "bob")
	if err == nil {
		t.Error("Revoked nonexistent file", err)
		return
	}
}

func TestUser_AppendFileBasic(t *testing.T) {
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

	text := []byte(" that will pass!")
	filetext := append(v, text...)
	err3 := u.AppendFile("file1", text)
	if err3 != nil {
		t.Error("Failed to append", err3)
	}

	v3, err4 := u.LoadFile("file1")
	if err4 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(filetext, v3) {
		t.Error("Append was not correct", v, v2)
		return
	}
}

func TestUser_AppendFileShare(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize alice", err)
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

	text := []byte(" that will pass!")
	filetext := append(v, text...)
	err3 := u.AppendFile("file1", text)
	if err3 != nil {
		t.Error("Failed to append", err3)
	}

	v3, err4 := u2.LoadFile("file2")
	if err4 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(filetext, v3) {
		t.Error("Append was not correct", v, v2)
		return
	}
	v2, err4 = u.LoadFile("file1")
	if err4 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(filetext, v2) {
		t.Error("Append was not correct", v, v2)
		return
	}
	if !reflect.DeepEqual(v2, v3) {
		t.Error("Append was not correct", v, v2)
		return
	}

	moreText := []byte(" Very cool")
	filetext = append(filetext, moreText...)
	err5 := u2.AppendFile("file2", moreText)
	if err5 != nil {
		t.Error("Failed to append", err5)
	}

	v4, err6 := u.LoadFile("file1")
	if err6 != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	if !reflect.DeepEqual(filetext, v4) {
		t.Error("Append was not correct", v, v2)
		return
	}


	u3, err := InitUser("charles", "peepee")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}
	u4, err := InitUser("dave", "poopoo")
	if err != nil {
		t.Error("Failed to initialize alice", err)
		return
	}

	magic_string, err = u2.ShareFile("file2", "charles")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u3.ReceiveFile("file3", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}

	magic_string, err = u2.ShareFile("file2", "dave")
	if err != nil {
		t.Error("Failed to share the a file", err)
		return
	}
	err = u4.ReceiveFile("file4", "bob", magic_string)
	if err != nil {
		t.Error("Failed to receive the share message", err)
		return
	}
	evenmoreText := []byte("aaaaaaaahhhhhhhhh")
	filetext = append(filetext, evenmoreText...)
	err5 = u3.AppendFile("file3", evenmoreText)
	if err5 != nil {
		t.Error("Failed to append", err5)
	}

	v, err = u.LoadFile("file1")
	if err != nil {
		t.Error("Failed to upload and download", err2)
		return
	}
	v3, err = u3.LoadFile("file3")
	if err != nil {
		t.Error("Failed to upload and download", err)
		return
	}
	v4, err = u4.LoadFile("file4")
	if err != nil {
		t.Error("Failed to upload and download", err)
		return
	}
	if !reflect.DeepEqual(v, v3) {
		t.Error("Append was not correct", v, v3)
		return
	}
	if !reflect.DeepEqual(v3, v4) {
		t.Error("Append was not correct", v3, v4)
		return
	}
	if !reflect.DeepEqual(v3, filetext) {
		t.Error("Append was not correct", v3, filetext)
		return
	}
}

func TestMessingWithDatastore(t *testing.T) {
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
	//t.Log("Got user", u)

	u2, err := GetUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to get existing user", err)
	}
	//t.Log("Got user", u2)

	var text = []byte("hello world")
	u.StoreFile("file1", text)

	loadedText, err := u2.LoadFile("file1")
	if err != nil {
		t.Error("failed to load existing file", err)
		return
	}
	if !reflect.DeepEqual(text, loadedText) {
		t.Error("loaded file was not same as stored")
		return
	}

	m := userlib.DatastoreGetMap()

	for key, value := range m {
		length := len(value)
		m[key] = value[:length - 2]
	}

	_, err = u2.LoadFile("file1")
	if err == nil {
		t.Error("Load should fail for file that was tampered with", err)
		return
	}
}

func TestInitSameUsername(t *testing.T) {
	clear()
	_, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	_, err = InitUser("alice", "foobar")
	if err == nil {
		t.Error("Initialized two users with same name", err)
		return
	}
}

func TestSameFileName(t *testing.T) {
	clear()
	u, err := InitUser("alice", "fubar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	u2, err := InitUser("bob", "foobar")
	if err != nil {
		t.Error("Failed to initialize user", err)
		return
	}
	v := []byte("This is a test")
	u.StoreFile("filename", v)
	var v2 []byte
	u2.StoreFile("otherfilename", v2)
	magic_string, err := u.ShareFile("filename", "bob")
	if err != nil {
		t.Error("Failed to share file", err)
		return
	}
	err = u2.ReceiveFile("otherfilename", "alice", magic_string)
	if err == nil {
		t.Error("Received file under existing name", err)
		return
	}
}

func TestSharingWithMultipleInstancesOfSameUser(t *testing.T) {

}

//If a user calls StoreFile on a filename that already exists, the file content is overwritten.
//	If the file has been shared with others, the file must stay shared.
func TestOverwriteStore(t *testing.T) {
	clear()
	u, _ := InitUser("alice", "fubar")
	u2, _ := InitUser("bob", "foobar")
	u3, _ := InitUser("charles", "abcde")

	v := []byte("This is a test")
	u.StoreFile("filename", v)

	magic_string, err := u.ShareFile("filename", "bob")
	err = u2.ReceiveFile("otherfilename", "alice", magic_string)

	magic_string, err = u2.ShareFile("otherfilename", "charles")
	err = u3.ReceiveFile("charlesfile", "bob", magic_string)

	v2 := []byte("newtext")
	u2.StoreFile("otherfilename", v2)

	v3, err1 := u.LoadFile("filename")
	if err1 != nil {
		t.Error("store overwrite did not maintain sharing", err)
		return
	}
	if !reflect.DeepEqual(v2, v3) {
		t.Error("store overwrite did not correctly update file")
		return
	}

	v4, err2 := u3.LoadFile("charlesfile")
	if err2 != nil {
		t.Error("store overwrite did not maintain sharing", err)
		return
	}
	if !reflect.DeepEqual(v2, v4) {
		t.Error("store overwrite did not correctly update file")
		return
	}

	v5 := []byte("newnewtext")
	u3.StoreFile("charlesfile", v5)
	v6, _:= u2.LoadFile("otherfilename")
	v7, _:= u.LoadFile("filename")

	if !reflect.DeepEqual(v6, v7) {
		t.Error("store overwrite did not update file for all people with access")
		return
	}
	if !reflect.DeepEqual(v5, v6) {
		t.Error("store overwrite did not update file correctly")
	}
}

//func TestRearrangingDatastore(t *testing.T) {
//	clear()
//
//	// You can set this to false!
//	userlib.SetDebugStatus(true)
//
//	u, err := InitUser("alice", "fubar")
//	if err != nil {
//		// t.Error says the test fails
//		t.Error("Failed to initialize user", err)
//		return
//	}
//
//	u2, err := GetUser("alice", "fubar")
//	if err != nil {
//		t.Error("Failed to get existing user", err)
//	}
//
//	var text = []byte("hello world")
//	u.StoreFile("file1", text)
//
//	var text2 = []byte("asdf123")
//	u.AppendFile("file1", text2)
//
//	m := userlib.DatastoreGetMap()
//
//	hashed, err := userlib.HMACEval(hashKey, []byte("file1" + "alice" + "fubar"))
//	contentsUUID, err := uuid.FromBytes(hashed[16:32])
//	//contentsMarshaled, _ := m[contentsUUID]
//	passwordKey := userlib.Argon2Key([]byte("fubar" + "password"), []byte("alice" + "username"), 32)
//	dataEncryptionKey, err := genHashKDFKey(passwordKey, "file1" + "fubar" + "alice" + "encryption", 32)
//	if err != nil {
//		return;
//	}
//	dataMACKey, err := genHashKDFKey(passwordKey, "file1" + "fubar" + "alice" + "encryptionMAC", 32)
//	if err != nil {
//		return
//	}
//	contentsMarshaled, _ := verifyAndDecrypt(dataEncryptionKey, dataMACKey, contentsUUID)
//	var contents FileContents
//	json.Unmarshal(contentsMarshaled, &contents)
//	userlib.DebugMsg("%d", contents.Index)
//
//	text1UUID := contents.IndexToContent[1]
//	text2UUID := contents.IndexToContent[2]
//
//	var contents1 = make([]byte, len(m[text1UUID.UUID]))
//	copy(contents1, m[text1UUID.UUID])
//	userlib.DebugMsg("%s", text1UUID.UUID)
//
//	var contents2 = make([]byte, len(m[text2UUID.UUID]))
//	userlib.DebugMsg("%s", text2UUID.UUID)
//
//	copy(contents2, m[text2UUID.UUID])
//
//	m[text2UUID.UUID] = contents1
//	m[text1UUID.UUID] = contents2
//
//	data, err1 := u2.LoadFile("file1")
//	if err1 == nil {
//		userlib.DebugMsg("%s", data)
//		t.Error("Load should fail for file that was tampered with by switching uuid -> file pointers", err)
//		return
//	}
//}
