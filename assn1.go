package assn1

// You MUST NOT change what you import.  If you add ANY additional
// imports it will break the autograder, and we will be Very Upset.

import (

	// You neet to add with
	// go get github.com/fenilfadadu/CS628-assn1/userlib
	"github.com/fenilfadadu/CS628-assn1/userlib"

	// Life is much easier with json:  You are
	// going to want to use this so you can easily
	// turn complex structures into strings etc...
	"encoding/json"

	// Likewise useful for debugging etc
	"encoding/hex"

	// UUIDs are generated right based on the crypto RNG
	// so lets make life easier and use those too...
	//
	// You need to add with "go get github.com/google/uuid"
	"github.com/google/uuid"

	// Useful for debug messages, or string manipulation for datastore keys
	"strings"

	// Want to import errors
	"errors"
)

// This serves two purposes: It shows you some useful primitives and
// it suppresses warnings for items not being imported
func someUsefulThings() {
	// Creates a random UUID
	f := uuid.New()
	userlib.DebugMsg("UUID as string:%v", f.String())

	// Example of writing over a byte of f
	f[0] = 10
	userlib.DebugMsg("UUID as string:%v", f.String())

	// takes a sequence of bytes and renders as hex
	h := hex.EncodeToString([]byte("fubar"))
	userlib.DebugMsg("The hex: %v", h)

	// Marshals data into a JSON representation
	// Will actually work with go structures as well
	d, _ := json.Marshal(f)
	userlib.DebugMsg("The json data: %v", string(d))
	var g uuid.UUID
	json.Unmarshal(d, &g)
	userlib.DebugMsg("Unmashaled data %v", g.String())

	// This creates an error type
	userlib.DebugMsg("Creation of error %v", errors.New(strings.ToTitle("This is an error")))

	// And a random RSA key.  In this case, ignoring the error
	// return value
	var key *userlib.PrivateKey
	key, _ = userlib.GenerateRSAKey()
	userlib.DebugMsg("Key is %v", key)
}

// Helper function: Takes the first 16 bytes and
// converts it into the UUID type
func bytesToUUID(data []byte) (ret uuid.UUID) {
	for x := range ret {
		ret[x] = data[x]
	}
	return
}

// The structure definition for a user record
type User struct {
	Username         string
	Password         string
	Filenamekeymap   map[string]string
	Fileshare        map[string]string   //for stroing (filename,key) pair
	Filenamelocation map[string][]byte   // for storing [filename][location,enc_key] pair
	Rsaprivatevkey   *userlib.PrivateKey // for RSA privatekey
	// You can add other fields here if you want...
	// Note for JSON to marshal/unmarshal, the fields need to
	// be public (start with a capital letter)
}

// This creates a user.  It will only be called once for a user
// (unless the keystore and datastore are cleared during testing purposes)

// It should store a copy of the userdata, suitably encrypted, in the
// datastore and should store the user's public key in the keystore.

// The datastore may corrupt or completely erase the stored
// information, but nobody outside should be able to get at the stored
// User data: the name used in the datastore should not be guessable
// without also knowing the password and username.

// You are not allowed to use any global storage other than the
// keystore and the datastore functions in the userlib library.

// You can assume the user has a STRONG password
func InitUser(username string, password string) (userdataptr *User, err error) {

	var userdata User
	err = nil
	userdata.Username = username //fetching username
	userdata.Password = password // fetching password

	//Calculating Argon2key

	userlocation, userdatakey := calculateinituserkey(username, password)

	Rsaprivatevkey, err := userlib.GenerateRSAKey()

	if err != nil {
		return nil, err

	}

	userdata.Rsaprivatevkey = Rsaprivatevkey

	userlib.KeystoreSet(username, Rsaprivatevkey.PublicKey) // Storing into KEystore

	userdata.Filenamekeymap = make(map[string]string)

	userdata.Fileshare = make(map[string]string)
	userdata.Filenamelocation = make(map[string][]byte)

	userdatamarshal, err := json.Marshal(userdata)

	if err != nil {
		return nil, err

	}

	// encrytping
	userdatamarshalenc, err := Encrypt(userdatamarshal, userdatakey)

	if err != nil {
		return nil, err
	}

	//mac calculation
	userdatamarshalencmac := HmacCalculate(userdatamarshalenc, userdatakey)

	stored, err := Encapsulate(userdatamarshalenc, userdatamarshalencmac)

	if err != nil {

		return nil, err
	}

	//Storing into Datastore

	userlib.DatastoreSet(string(userlocation), stored)

	return &userdata, err
}

// This fetches the user information from the Datastore.  It should
// fail with an error if the user/password is invalid, or if the user
// data was corrupted, or if the user can't be found.
func GetUser(username string, password string) (userdataptr *User, err error) {

	userlocation, userdatakey := calculateinituserkey(username, password)

	fetchedencrypteddatauser, okpresent := userlib.DatastoreGet(string(userlocation))

	if !okpresent {

		err = errors.New("username not found or pass incorrect")
		return nil, err
	}

	// Validating MAC

	type List struct { //Declaring structure
		Encval []byte
		Hmac   []byte
	}

	var l List
	err = json.Unmarshal(fetchedencrypteddatauser, &l)
	if err != nil {
		return nil, err
	}

	calcmac := HmacCalculate(l.Encval, userdatakey)

	if !userlib.Equal(calcmac, l.Hmac) {
		err = errors.New("Userdata tampered")
		return nil, err

	}

	//decrypting

	userdatadec, err := Decrypt(l.Encval, userdatakey)

	if err != nil {
		return nil, err
	}

	var userdataget User
	err = json.Unmarshal(userdatadec, &userdataget)
	if err != nil {

		return nil, err
	}
	return &userdataget, err
}

// This stores a file in the datastore.
//
// The name of the file should NOT be revealed to the datastore!
func (userdata *User) StoreFile(filename string, data []byte) {

	//Fetching current user data

	var currentuser *User
	currentuser, _ = GetUser(userdata.Username, userdata.Password)

	userdata.Username = currentuser.Username
	userdata.Password = currentuser.Password
	userdata.Filenamekeymap = currentuser.Filenamekeymap
	userdata.Fileshare = currentuser.Fileshare
	userdata.Filenamelocation = currentuser.Filenamelocation
	userdata.Rsaprivatevkey = currentuser.Rsaprivatevkey

	fileenckeystr := uuid.New().String()

	var indtab []string
	newindtabenckey := []byte(fileenckeystr)[0:userlib.AESKeySize]

	newfileenckey := []byte(fileenckeystr + "0")[0:userlib.AESKeySize]

	newindexloc := string(userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename), []byte{}, 16))
	newindexloc = newindexloc
	newfileloc := string(userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename+"0"), []byte{}, 16))

	indtab = append(indtab, newfileloc)

	var indtab2 []string

	// encrypting index table
	indtabmarshal, _ := json.Marshal(indtab)
	json.Unmarshal(indtabmarshal, &indtab2)
	indtabencbytes, _ := Encrypt(indtabmarshal, newindtabenckey)

	// mac of indextable
	indtabencbytesmac := HmacCalculate(indtabencbytes, newindtabenckey)

	stored, _ := Encapsulate(indtabencbytes, indtabencbytesmac)

	//final storing of indextable

	userlib.DatastoreSet(newindexloc, stored)

	// encrypting file

	fileencmarshal, _ := Encrypt(data, newfileenckey)

	// mac of file

	filedatabytesmac := HmacCalculate(fileencmarshal, newfileenckey)

	stored, _ = Encapsulate(fileencmarshal, filedatabytesmac)

	//storing file contents
	userlib.DatastoreSet(indtab2[0], stored)

	userdata.Filenamekeymap[filename] = fileenckeystr

	// updating the user

	// encrypting user contents

	userdatamarshal, _ := json.Marshal(userdata)
	userlocation, userdatakey := calculateinituserkey(userdata.Username, userdata.Password)
	userdataenc, _ := Encrypt(userdatamarshal, userdatakey)

	// mac of file

	userdatamac := HmacCalculate(userdataenc, userdatakey)

	stored, _ = Encapsulate(userdataenc, userdatamac)

	//storing file contents
	userlib.DatastoreSet(string(userlocation), stored)

}

// This adds on to an existing file.
//
// Append should be efficient, you shouldn't rewrite or reencrypt the
// existing file, but only whatever additional information and
// metadata you need.

func (userdata *User) AppendFile(filename string, data []byte) (err error) {

	//Fetching current userdata
	var currentuser *User
	currentuser, _ = GetUser(userdata.Username, userdata.Password)
	userdata.Username = currentuser.Username
	userdata.Password = currentuser.Password
	userdata.Filenamekeymap = currentuser.Filenamekeymap
	userdata.Fileshare = currentuser.Fileshare
	userdata.Filenamelocation = currentuser.Filenamelocation
	userdata.Rsaprivatevkey = currentuser.Rsaprivatevkey

	// index file encryption key
	var indtabenckey []byte
	var indexloc string
	indtabenckeystr, got := userdata.Filenamekeymap[filename]
	if len(data) > 0 { //checking if the data is non null
		if got {
			indexloc = string(userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename), []byte{}, 16))

		} else {
			indtabenckeystr, got = userdata.Fileshare[filename]
			indexlocb, got := userdata.Filenamelocation[filename]
			indexloc = string(indexlocb)

			if !got {
				err = errors.New("filename not found")
				return err
			}
		}
	}
	indtabenckey = []byte(indtabenckeystr)[0:userlib.AESKeySize]
	// fetching index file
	fetchedencryptedfileindex, okpresent := userlib.DatastoreGet(indexloc)
	if !okpresent {

		err = errors.New("file metadata not found")
		return err
	}

	// Validating MAC

	type List struct {
		Encval []byte
		Hmac   []byte
	}

	var l List
	err = json.Unmarshal(fetchedencryptedfileindex, &l)
	if err != nil {
		return err
	}

	calcmac := HmacCalculate(l.Encval, indtabenckey)

	if !userlib.Equal(calcmac, l.Hmac) {
		err = errors.New("Indexfile tampered")
		return err

	}

	//Decrypt Indextable

	indexdatadec, err := Decrypt(l.Encval, indtabenckey)

	if err != nil {
		return err
	}

	var indtab []string
	err = json.Unmarshal(indexdatadec, &indtab)
	if err != nil {

		return err
	}

	// New File location
	//converting len(indtab) to its string form
	num := len(indtab)
	istring := ""
	if num == 0 {

		istring = "0"

	} else {

		for num != 0 {

			dig := num%10 + 48

			istring = string(dig) + istring
			num = num / 10

		}
	}
	newfileloc := string(userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename+istring), []byte{}, 16))
	newfileloc = newfileloc

	fileenckey := []byte(indtabenckeystr + istring)[0:userlib.AESKeySize]

	indtab = append(indtab, newfileloc)

	var indtab2 []string

	// encrypting index table
	indtabmarshal, _ := json.Marshal(indtab)
	json.Unmarshal(indtabmarshal, &indtab2)
	indtabencbytes, _ := Encrypt(indtabmarshal, indtabenckey)

	// mac of indextable
	indtabencbytesmac := HmacCalculate(indtabencbytes, indtabenckey)

	stored, _ := Encapsulate(indtabencbytes, indtabencbytesmac)

	//final storing of indextable

	userlib.DatastoreSet(indexloc, stored)

	// new file content key

	filedataenc, err := Encrypt(data, fileenckey)
	if err != nil {
		return err
	}
	//hmac calc

	filedataencmac := HmacCalculate(filedataenc, fileenckey)
	store, err := Encapsulate(filedataenc, filedataencmac)

	if err != nil {
		return err
	}
	userlib.DatastoreSet(indtab2[len(indtab)-1], store)

	return err

}

// This loads a file from the Datastore.
//
// It should give an error if the file is corrupted in any way.
func (userdata *User) LoadFile(filename string) (data []byte, err error) {
	//Fecthing current Userdata

	currentuser, _ := GetUser(userdata.Username, userdata.Password)
	userdata.Username = currentuser.Username
	userdata.Password = currentuser.Password
	userdata.Filenamekeymap = currentuser.Filenamekeymap
	userdata.Fileshare = currentuser.Fileshare
	userdata.Filenamelocation = currentuser.Filenamelocation
	userdata.Rsaprivatevkey = currentuser.Rsaprivatevkey

	//load encrypted contents
	var indtabenckey []byte
	var indexloc string
	var indexlocb []byte
	indtabenckeystr, got := userdata.Filenamekeymap[filename]
	if len(filename) > 0 { //checking if the filename is not null
		if got {
			indexloc = string(userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename), []byte{}, 16))

		} else {
			indtabenckeystr, got = userdata.Fileshare[filename]
			indexlocb, got = userdata.Filenamelocation[filename]
			indexloc = string(indexlocb)

			if !got {
				err = errors.New("filename not found")
				return nil, err
			}
		}
	}
	indtabenckey = []byte(indtabenckeystr)[0:userlib.AESKeySize]

	err = nil
	fetchedencryptedfileindex, okpresent := userlib.DatastoreGet(indexloc) //fetch from Datastore
	if !okpresent {

		err = errors.New("file metadata not found")
		return nil, err
	}

	//Validating MAC

	type List struct {
		Encval []byte
		Hmac   []byte
	}

	var l List
	err = json.Unmarshal(fetchedencryptedfileindex, &l)
	if err != nil {
		return nil, err
	}

	calcmac := HmacCalculate(l.Encval, indtabenckey)

	if !userlib.Equal(calcmac, l.Hmac) {
		err = errors.New("Userdata tampered")
		return nil, err

	}

	// decrypting

	indexdatadec, err := Decrypt(l.Encval, indtabenckey)

	if err != nil {
		return nil, err
	}

	var indtab []string
	err = json.Unmarshal(indexdatadec, &indtab)
	if err != nil {

		return nil, err
	}

	for i := 0; i < len(indtab); i = i + 1 {
		if len(filename) > 0 && i >= 0 && i < len(indtab) { //checking if the filename is not null and i is within range
			filelocithkey := indtab[i]

			//converting i to its string form
			num := i
			istring := ""
			if num == 0 {

				istring = "0"

			} else {

				for num != 0 {

					dig := num%10 + 48

					istring = string(dig) + istring
					num = num / 10

				}
			}

			filekeyithkeystr := indtabenckeystr + istring

			filekeyithkey := []byte(filekeyithkeystr)[0:userlib.AESKeySize]

			// getting file encerypted contents

			filecontentrecvd, okpresent := userlib.DatastoreGet(filelocithkey)

			if !okpresent {

				err = errors.New("file chunk not found")
				return nil, err
			}

			err = json.Unmarshal(filecontentrecvd, &l)
			if err != nil {

				return nil, err
			}

			filecontentrecvdcalcmac := HmacCalculate(l.Encval, filekeyithkey)

			if !userlib.Equal(filecontentrecvdcalcmac, l.Hmac) {

				err = errors.New("File chunk corrupted ")
				return nil, err
			}

			// decrypting ith chunk

			filechunkdec, err := Decrypt(l.Encval, filekeyithkey)

			if err != nil {

				return nil, err
			}

			bytechunk := filechunkdec
			if err != nil {

				return nil, err
			}

			data = append(data[:], bytechunk[:]...)
		}

	}

	return data, err
}

// You may want to define what you actually want to pass as a
// sharingRecord to serialized/deserialize in the data store.
type sharingRecord struct {
	Loc []byte
	Key string
}

// This creates a sharing record, which is a key pointing to something
// in the datastore to share with the recipient.

// This enables the recipient to access the encrypted file as well
// for reading/appending.

// Note that neither the recipient NOR the datastore should gain any
// information about what the sender calls the file.  Only the
// recipient can access the sharing record, and only the recipient
// should be able to know the sender.

func (userdata *User) ShareFile(filename string, recipient string) (

	msgid string, err error) {
	//var err error
	err = nil

	//Fetching current userdata

	var currentuser *User
	currentuser, _ = GetUser(userdata.Username, userdata.Password)
	userdata.Username = currentuser.Username
	userdata.Password = currentuser.Password
	userdata.Filenamekeymap = currentuser.Filenamekeymap
	userdata.Fileshare = currentuser.Fileshare
	userdata.Filenamelocation = currentuser.Filenamelocation
	userdata.Rsaprivatevkey = currentuser.Rsaprivatevkey

	//var indtabenckey []byte
	var share sharingRecord
	type Encapsulation struct {
		Sharemarshalenc []byte
		Sign            []byte
	}
	var sending Encapsulation
	var indexloc string
	publickey, got := userlib.KeystoreGet(recipient)
	if !got {
		err = errors.New("public key missing")
		return "", err
	}
	indtabenckeystr, got := userdata.Filenamekeymap[filename]
	var indexlocb []byte
	if len(recipient) > 0 { //checking if the recipient name  is not null
		if got {
			indexloc = string(userlib.Argon2Key([]byte(userdata.Username+userdata.Password+filename), []byte{}, 16))
			indexlocb = []byte(indexloc)

		} else {
			indtabenckeystr, got = userdata.Fileshare[filename]
			indexlocb, got = userdata.Filenamelocation[filename]
			indexloc = string(indexlocb)

			if !got {
				err = errors.New("filename not found")
				return "", err
			}

		}
	}

	share.Key = indtabenckeystr
	share.Loc = indexlocb

	sharemarshal, err := json.Marshal(share)

	if err != nil {
		return "", err
	}
	//signing encrypting and sending

	sharemarshalenc, err := userlib.RSAEncrypt(&publickey, sharemarshal, []byte{})

	if err != nil {
		return "", err
	}
	sign, err := userlib.RSASign(userdata.Rsaprivatevkey, sharemarshalenc)
	if err != nil {
		return "", err
	}

	sending.Sharemarshalenc = sharemarshalenc
	sending.Sign = sign

	sendingmarshal, err := json.Marshal(sending)
	if err != nil {
		return "", err
	}
	m := string(sendingmarshal)

	return m, err

}

// Note recipient's filename can be different from the sender's filename.
// The recipient should not be able to discover the sender's view on
// what the filename even is!  However, the recipient must ensure that
// it is authentically from the sender.
func (userdata *User) ReceiveFile(filename string, sender string,
	msgid string) error {

	var err error

	//Fetching current userdata

	var currentuser *User
	if len(sender) > 0 {
		currentuser, _ = GetUser(userdata.Username, userdata.Password)
		userdata.Username = currentuser.Username
		userdata.Password = currentuser.Password
		userdata.Filenamekeymap = currentuser.Filenamekeymap
		userdata.Fileshare = currentuser.Fileshare
		userdata.Filenamelocation = currentuser.Filenamelocation
		userdata.Rsaprivatevkey = currentuser.Rsaprivatevkey
	}
	type Encapsulation struct {
		Sharemarshalenc []byte
		Sign            []byte
	}
	//var err error

	err = nil
	var mr Encapsulation

	err = json.Unmarshal([]byte(msgid), &mr)

	if err != nil {
		return err
	}

	publickey, got := userlib.KeystoreGet(sender)

	if !got {
		err = errors.New("public key missing")
		return err

	}

	err = userlib.RSAVerify(&publickey, mr.Sharemarshalenc, mr.Sign)

	if err != nil {
		return err
	} else {
		decsharinginfo, err := userlib.RSADecrypt(userdata.Rsaprivatevkey, mr.Sharemarshalenc, []byte{})
		if err != nil {
			return err
		}

		var sharing sharingRecord
		err = json.Unmarshal(decsharinginfo, &sharing)

		if err != nil {
			return err
		}

		userdata.Fileshare[filename] = sharing.Key
		userdata.Filenamelocation[filename] = sharing.Loc

		userdatamarshal, _ := json.Marshal(userdata)
		userlocation, userdatakey := calculateinituserkey(userdata.Username, userdata.Password)
		userdataenc, _ := Encrypt(userdatamarshal, userdatakey)

		// mac of file

		userdatamac := HmacCalculate(userdataenc, userdatakey)

		stored, _ := Encapsulate(userdataenc, userdatamac)

		//storing file contents
		userlib.DatastoreSet(string(userlocation), stored)
		return err

		//update user
	}
	// encrypting user contents

}

// Removes access for all others.
func (userdata *User) RevokeFile(filename string) (err error) {

	err = nil

	//Fetching current userdata

	var currentuser *User
	currentuser, _ = GetUser(userdata.Username, userdata.Password)
	userdata.Username = currentuser.Username
	userdata.Password = currentuser.Password
	userdata.Filenamekeymap = currentuser.Filenamekeymap
	userdata.Fileshare = currentuser.Fileshare
	userdata.Filenamelocation = currentuser.Filenamelocation
	userdata.Rsaprivatevkey = currentuser.Rsaprivatevkey

	data, err := userdata.LoadFile(filename)

	if err != nil {
		return err
	}
	userdata.StoreFile(filename, data)
	return err
}

func Encrypt(msgmarshalbytes []byte, encryptionkey []byte) (encryptedbytes []byte, err error) {

	encryptedbytes = make([]byte, userlib.BlockSize+len(msgmarshalbytes)) //needs to be stored
	err = nil
	iv := userlib.RandomBytes(userlib.BlockSize)
	i := 0
	for i < userlib.BlockSize {
		encryptedbytes[i] = iv[i]
		i = i + 1
	}

	iv = encryptedbytes[:userlib.BlockSize]
	stream := userlib.CFBEncrypter(encryptionkey, iv)
	stream.XORKeyStream(encryptedbytes[userlib.BlockSize:], msgmarshalbytes)

	return encryptedbytes, err

}

func Decrypt(encmsgmarshalbytes []byte, decryptionkey []byte) (encryptedbytes []byte, err error) {
	err = nil
	iv := encmsgmarshalbytes[:userlib.BlockSize]
	encmsgmarshalbytes = encmsgmarshalbytes[userlib.BlockSize:]

	stream := userlib.CFBDecrypter(decryptionkey, iv)
	stream.XORKeyStream(encmsgmarshalbytes, encmsgmarshalbytes)

	return encmsgmarshalbytes, err

}

func HmacCalculate(msgmarshalbytes []byte, encryptionkey []byte) (hmacdata []byte) {
	hmac := userlib.NewHMAC(encryptionkey)
	hmac.Write(msgmarshalbytes)

	hmacdata = hmac.Sum(nil) //needt to be stored

	return hmacdata
}

func calculateinituserkey(username string, password string) (userlocation []byte, userdatakey []byte) {

	argonkey := userlib.Argon2Key([]byte(username+password), []byte{}, 32)

	userlocation = argonkey[0 : len(argonkey)/2]

	userdatakey = argonkey[len(argonkey)/2 : len(argonkey)]

	return userlocation, userdatakey
}

func Encapsulate(data []byte, mac []byte) (lb []byte, err error) {

	type List struct {
		Encval []byte
		Hmac   []byte
	}

	err = nil
	var l List
	l.Encval = data
	l.Hmac = mac

	lb, err = json.Marshal(l)
	return lb, err

}
