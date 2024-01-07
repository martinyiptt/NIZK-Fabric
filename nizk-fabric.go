/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// ver camera ready, Martin Yip

package main


import (
    "fmt"
    "strconv"
    "encoding/json"
    "math/big"
    "crypto/sha256"
    "encoding/binary"
    "time"
    
    "github.com/zkLedger_cc/go/zksigma/btcec"
    "github.com/zkLedger_cc/go/zksigma"

    "github.com/hyperledger/fabric/core/chaincode/shim"
    pb "github.com/hyperledger/fabric/protos/peer"
)

var logger = shim.NewLogger("zk_cc0")

const (
    Transfer TXN_TYPE = iota
    Issuance
    Withdrawal
)

type TXN_TYPE int

type CacheListStruct struct {
    CommsCache []zksigma.ECPoint
    RTokenCache []zksigma.ECPoint
}

type RandomnessListStruct struct {
    //this has to be same as num
    R [4]*big.Int
}

type Entry struct {
    Bank    int
    Comm    zksigma.ECPoint // A_i
    RToken  zksigma.ECPoint // B_i
    V       *big.Int        // unencrypted value for testing and issuance/withdrawal
    R       *big.Int        // value for testing
    CommAux zksigma.ECPoint // cm_{aux,i},
    BAux    zksigma.ECPoint // B_{aux,i} g^v*h^r'
    // Proof of well-formedness (r_i's match, v is 0 or I know sk)
    //WellFormed      EquivORLogProof // "I know x st x = log_h(A_i) = log_{pk_i}(B_i) OR I know y st y = log_h(pk_i)"
    CommConsistency *zksigma.ConsistencyProof
    AuxConsistency  *zksigma.ConsistencyProof
    Assets          *zksigma.DisjunctiveProof // "cm_{aux,i}~\sum{cm_col} OR cm_{aux,i}~cm_i"
    RP              *zksigma.RangeProof       // cm_{aux,i} >= 0
    BAuxR           *big.Int                  // Intermediately hold r here so I can generate the Range Proof outside of createLocal (holding the lock in ledger)
    SKProof         *zksigma.GSPFSProof       // Proof of knowledge of SK for issuance (issuer) or withdrawal (Bank)
}

type EncryptedTransaction struct {
    Index      int ``
    TS         time.Time
    Type       TXN_TYPE
    Sender     int // testing
    Receiver   int // testing
    Entries    []Entry
    skipVerify bool // Only for testing; default false
}

type Bank struct {
    Id  int
    Num int
    Pki *PKI
    CommsCache []zksigma.ECPoint    
    RTokenCache []zksigma.ECPoint   
}
type PKI struct {
    PK []zksigma.ECPoint
    SK []*big.Int
}

var ZKLedgerCurve zksigma.ZKPCurveParams
var Id int
var Num = 4
var pki PKI 
var etxJson string
var err error

var CommsCache []zksigma.ECPoint    
var RTokenCache []zksigma.ECPoint
var CacheList CacheListStruct    

// SimpleChaincode example simple Chaincode implementation
type SimpleChaincode struct {
}

func (t *SimpleChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response  {
    logger.Info("########### ak_cc0 Init ###########")
    
    pkiJson := `{"PK": [
    {"X": 31162737974914322510223911493259949908325790533701417645370598536038546760813,"Y": 3243957534678192772627433866145815496382252068439063004526717165758982279478}, 
    {"X": 104306669726597258552457800704291913924157442819741684968539853652305339195302,"Y": 59723646933547178320805231501800256566404530244961528445232623018526217031402}, 
    {"X": 78990978055875482213519426577566655084235914353126259846189426580585978191425,"Y": 14838356030615363985994465553279457831477711117352611982834955835709977276603}, 
    {"X": 60284213037711622963860348272688379503451660376614053888286834031195565953917,"Y": 31555205998050805369326328704358754043154607628971344387956391519812942635882}, 
    {"X": 104597657332180700732862897786513766669655094268388302589461598923822453112374,"Y": 51659256023242095536989650590244254087257334458253939072448084726506084032326}]}` 

    var pki PKI 
    json.Unmarshal([]byte(pkiJson), &pki)

    // init 
     s256 := sha256.New()

    // // This was changed in ZKSigma, but keys already generated part of the repo
    // // should still work. So reverted this to what was originally in ZKLedger,

    // see:
    // hashedString := s256.Sum([]byte("This is the new random point in zksigma"))
    // HX, HY := btcec.S256().ScalarMult(btcec.S256().Gx, btcec.S256().Gy, hashedString)
    curValue := btcec.S256().Gx
    s256.Write(new(big.Int).Add(curValue, big.NewInt(2)).Bytes()) // hash G_x + 2 which

    potentialXValue := make([]byte, 33)
    binary.LittleEndian.PutUint32(potentialXValue, 2)
    for i, elem := range s256.Sum(nil) {
        potentialXValue[i+1] = elem
    }

    H, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
    if err != nil {
        panic(err)
    }
    ZKLedgerCurve = zksigma.ZKPCurveParams{
        C: btcec.S256(),
        G: zksigma.ECPoint{btcec.S256().Gx, btcec.S256().Gy},
        H: zksigma.ECPoint{H.X, H.Y},
    }
    ZKLedgerCurve.HPoints = generateH2tothe()

    // Put the zkcurve into the chain
    // convert ZKCurve to []byte
    ZKLedgerCurveAsJSONBytes, _ := json.Marshal(ZKLedgerCurve)
    // add bank to ledger, bank id as a key, bankAsJSONBytes as the value
    //logger.Info("b as byte = %d \n", bankAsJSONBytes)
    
    ZKLedgerCurveKey := "ZKLedgerCurveKey"
    err = stub.PutState(ZKLedgerCurveKey, []byte(ZKLedgerCurveAsJSONBytes))

    if err != nil {
        return shim.Error("Failed to create ZKLedgerCurve ")
    }

    return shim.Success([]byte("Init - caches created successfully."))
}

// Transaction makes payment of X units from A to B
func (t *SimpleChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
    //logger.Info("########### example_cc0 Invoke ###########")

    function, args := stub.GetFunctionAndParameters()
    
    if function == "add" {
        // add an entity from its state
        return t.add(stub, args)
    } else if function == "addIssuance" {
        // add an entity from its state
        return t.addIssuance(stub, args)
    } else if function == "query" {
        // add an entity from its state
        return t.query(stub, args)
    } else if function == "addProofofAssets" {
        // add an entity from its state
        return t.addProofofAssets(stub, args)
    }
     
    return shim.Success([]byte("Invoke successful."))

    logger.Errorf("Unknown action, check the first argument, must be one of 'add', 'query'. But got: %v", args[0])
    return shim.Error(fmt.Sprintf("Unknown action, check the first argument, must be one of 'add', or 'query'. But got: %v", args[0]))
}

func (t *SimpleChaincode) addIssuance(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    //logger.Info("########### example_cc0 addIssuance ###########")

    pkiJson := `{"PK": [
    {"X": 31162737974914322510223911493259949908325790533701417645370598536038546760813,"Y": 3243957534678192772627433866145815496382252068439063004526717165758982279478}, 
    {"X": 104306669726597258552457800704291913924157442819741684968539853652305339195302,"Y": 59723646933547178320805231501800256566404530244961528445232623018526217031402}, 
    {"X": 78990978055875482213519426577566655084235914353126259846189426580585978191425,"Y": 14838356030615363985994465553279457831477711117352611982834955835709977276603}, 
    {"X": 60284213037711622963860348272688379503451660376614053888286834031195565953917,"Y": 31555205998050805369326328704358754043154607628971344387956391519812942635882}, 
    {"X": 104597657332180700732862897786513766669655094268388302589461598923822453112374,"Y": 51659256023242095536989650590244254087257334458253939072448084726506084032326}]}` 

    var pki PKI 
    json.Unmarshal([]byte(pkiJson), &pki)
    ZKLedgerCurveKey := "ZKLedgerCurveKey"
    var err error
    
    // Check if the invoke request has exactly 1 arg
    if len(args) != 1 {
        return shim.Error("Incorrect number of arguments. Expecting 1, function followed by 2 names and 1 value")
    }

    etxJson := args[0]
    if etxJson == "" {
        return shim.Error("etxJson not found")
    }

    // convert it to meaningful byte as zkledger etx
    var etx EncryptedTransaction    
    json.Unmarshal([]byte(etxJson), &etx)
    
    etxKey := "etx" + strconv.Itoa(etx.Index)

    // Get the ZKLedgerCurve state from the ledger
    ZKLedgerCurveAsBytes, err := stub.GetState(ZKLedgerCurveKey)
    if err != nil {
        jsonResp := "{\"Error\":\"Failed to get state for ZKLedgerCurve\"}"
        return shim.Error(jsonResp)
    }
    if ZKLedgerCurveAsBytes == nil {
        return shim.Error("Failed to get state of ZKLedgerCurve")
    }

    //Construct the struct ZKLedgerCurve

    // init 
     s256 := sha256.New()

    // // This was changed in ZKSigma, but keys already generated part of the repo
    // // should still work. So reverted this to what was originally in ZKLedger,

    // see:
    // hashedString := s256.Sum([]byte("This is the new random point in zksigma"))
    // HX, HY := btcec.S256().ScalarMult(btcec.S256().Gx, btcec.S256().Gy, hashedString)
    curValue := btcec.S256().Gx
    s256.Write(new(big.Int).Add(curValue, big.NewInt(2)).Bytes()) // hash G_x + 2 which

    potentialXValue := make([]byte, 33)
    binary.LittleEndian.PutUint32(potentialXValue, 2)
    for i, elem := range s256.Sum(nil) {
        potentialXValue[i+1] = elem
    }

    H, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
    if err != nil {
        panic(err)
    }
    ZKLedgerCurve = zksigma.ZKPCurveParams{
        C: btcec.S256(),
        G: zksigma.ECPoint{btcec.S256().Gx, btcec.S256().Gy},
        H: zksigma.ECPoint{H.X, H.Y},
    }
    ZKLedgerCurve.HPoints = generateH2tothe()

    _ = json.Unmarshal(ZKLedgerCurveAsBytes, &ZKLedgerCurve)

    start := time.Now()
    if !etx.Verify(pki.PK, fmt.Sprintf("%d", Id)) {
            return shim.Error("Transaction does not verify!!!")
    }
    elapsed := time.Since(start)
    etxAsJSONBytes, _ := json.Marshal(etx)

    // Write the state back to the ledger
    err = stub.PutState(etxKey, []byte(etxAsJSONBytes))
    if err != nil {
        return shim.Error("Failed to write transcation " + etxKey)
    }

    CommsCacheJson := `[{"X": 0,"Y": 0},{"X": 0,"Y": 0},{"X": 0,"Y": 0},{"X": 0,"Y": 0}]`
    RTokenCacheJson := `[{"X": 0,"Y": 0},{"X": 0,"Y": 0},{"X": 0,"Y": 0},{"X": 0,"Y": 0}]`

    var CommsCache []zksigma.ECPoint    
    json.Unmarshal([]byte(CommsCacheJson), &CommsCache)

    var RTokenCache []zksigma.ECPoint   
    json.Unmarshal([]byte(RTokenCacheJson), &RTokenCache)
   
    en := &etx.Entries[etx.Sender]
    gval := ZKLedgerCurve.Mult(ZKLedgerCurve.G, en.V)
    CommsCache[etx.Sender] = ZKLedgerCurve.Add(CommsCache[etx.Sender], gval)

    CacheListKey := "CacheList" + strconv.Itoa(etx.Index)
    CacheList = CacheListStruct{CommsCache: CommsCache, RTokenCache: RTokenCache}
    CacheListAsJSONBytes, _ := json.Marshal(CacheList)

    err = stub.PutState(CacheListKey, []byte(CacheListAsJSONBytes))
    if err != nil {
        return shim.Error("Failed to write transcation " + CacheListKey)
    }
    logger.Info("Cache list Updated \n", CacheListKey)


    return shim.Success([]byte("Transaction Updated."));
}



func (t *SimpleChaincode) add(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    //logger.Info("########### example_cc0 add ###########")
 
    pkiJson := `{"PK": [
    {"X": 31162737974914322510223911493259949908325790533701417645370598536038546760813,"Y": 3243957534678192772627433866145815496382252068439063004526717165758982279478}, 
    {"X": 104306669726597258552457800704291913924157442819741684968539853652305339195302,"Y": 59723646933547178320805231501800256566404530244961528445232623018526217031402}, 
    {"X": 78990978055875482213519426577566655084235914353126259846189426580585978191425,"Y": 14838356030615363985994465553279457831477711117352611982834955835709977276603}, 
    {"X": 60284213037711622963860348272688379503451660376614053888286834031195565953917,"Y": 31555205998050805369326328704358754043154607628971344387956391519812942635882}, 
    {"X": 104597657332180700732862897786513766669655094268388302589461598923822453112374,"Y": 51659256023242095536989650590244254087257334458253939072448084726506084032326}]}` 

    var pki PKI 
    json.Unmarshal([]byte(pkiJson), &pki)

    ZKLedgerCurveKey := "ZKLedgerCurveKey"
    var err error
  
    // Check if the invoke request has exactly 1 arg
    if len(args) != 1 {
        return shim.Error("Incorrect number of arguments.")
    }
    // move the zkledger curve up
    // Get the ZKLedgerCurve state from the ledger
    ZKLedgerCurveAsBytes, err := stub.GetState(ZKLedgerCurveKey)
    if err != nil {
        jsonResp := "{\"Error\":\"Failed to get state for ZKLedgerCurve\"}"
        return shim.Error(jsonResp)
    }
    if ZKLedgerCurveAsBytes == nil {
        return shim.Error("Failed to get state of ZKLedgerCurve")
    }

    //Construct the struct ZKLedgerCurve
    // init 
    s256 := sha256.New()

    // // This was changed in ZKSigma, but keys already generated part of the repo
    // // should still work. So reverted this to what was originally in ZKLedger,

    // see:
    // hashedString := s256.Sum([]byte("This is the new random point in zksigma"))
    // HX, HY := btcec.S256().ScalarMult(btcec.S256().Gx, btcec.S256().Gy, hashedString)
    curValue := btcec.S256().Gx
    s256.Write(new(big.Int).Add(curValue, big.NewInt(2)).Bytes()) // hash G_x + 2 which

    potentialXValue := make([]byte, 33)
    binary.LittleEndian.PutUint32(potentialXValue, 2)
    for i, elem := range s256.Sum(nil) {
        potentialXValue[i+1] = elem
    }

    H, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
    if err != nil {
        panic(err)
    }
    ZKLedgerCurve = zksigma.ZKPCurveParams{
        C: btcec.S256(),
        G: zksigma.ECPoint{btcec.S256().Gx, btcec.S256().Gy},
        H: zksigma.ECPoint{H.X, H.Y},
    }
    ZKLedgerCurve.HPoints = generateH2tothe()
    
    //ZKLedgerCurve := zksigma.ZKPCurveParams{}
    _ = json.Unmarshal(ZKLedgerCurveAsBytes, &ZKLedgerCurve)
    //logger.Info("ZKLedgerCurve = %d\n", ZKLedgerCurve)

    var etx [1] EncryptedTransaction    
    for i := 0; i < 1; i++{
        //fmt.Println("Bank[",b.id,"] ", " postTransaction - etxID = ", etx[i].Index )
        //etxJson[i], _ = json.Marshal(string(json.Marshal(etx[i])))

        // convert the etx args to meaningful byte as zkledger etx

        etxJson := args[i]

        if etxJson == "" {
            return shim.Error("etxJson not found")
        }

        json.Unmarshal([]byte(etxJson), &etx[i])

        etxKey := "etx" + strconv.Itoa(etx[i].Index)
        etxAsBytes, err := stub.GetState(etxKey)
        if err != nil {
            jsonResp := "{\"Error\":\"Failed to get state for " + etxKey + "\"}"
            return shim.Error(jsonResp)
        }else if etxAsBytes != nil {
            return shim.Error("Transcation" + etxKey + "already exists, you cannot create a transcation with the same ID")
        }

        //Verify the transcation
        // if the transcation does not verify, reject the transcation
        // if it verifies, write the transcations to the ledger
        start := time.Now()
         if !etx[i].Verify(pki.PK, fmt.Sprintf("%d", Id)) {
                return shim.Error("Transaction does not verify!!!")
        }
        elapsed := time.Since(start)
        logger.Info("Transcation Verify took %s", elapsed)
       
        etxAsJSONBytes, _ := json.Marshal(etx[i])

        // Write the state back to the ledger
        err = stub.PutState(etxKey, []byte(etxAsJSONBytes))
        if err != nil {
            return shim.Error("Failed to write transcation " + etxKey)
        }

        //update cache list
        CommsCacheJson := `[{"X": 0,"Y": 0},{"X": 0,"Y": 0},{"X": 0,"Y": 0},{"X": 0,"Y": 0}]`
        RTokenCacheJson := `[{"X": 0,"Y": 0},{"X": 0,"Y": 0},{"X": 0,"Y": 0},{"X": 0,"Y": 0}]`

        var CommsCache []zksigma.ECPoint    
        json.Unmarshal([]byte(CommsCacheJson), &CommsCache)

        var RTokenCache []zksigma.ECPoint   
        json.Unmarshal([]byte(RTokenCacheJson), &RTokenCache)

         for j := 0; j < Num; j++ {
            RTokenCache[j] = ZKLedgerCurve.Add(RTokenCache[j], etx[i].Entries[j].RToken)
            CommsCache[j] = ZKLedgerCurve.Add(CommsCache[j], etx[i].Entries[j].Comm)
        }
    
        CacheList = CacheListStruct{CommsCache: CommsCache, RTokenCache: RTokenCache}
        CacheListAsJSONBytes, _ := json.Marshal(CacheList)
        CacheListKey := "CacheList" + strconv.Itoa(etx[i].Index)

        err = stub.PutState(CacheListKey, []byte(CacheListAsJSONBytes))
        if err != nil {
            return shim.Error("Failed to write cache list " + CacheListKey)
        }
        logger.Info("Cache list Updated \n", CacheListKey)

    }
   
    return shim.Success([]byte("Transactions Updated."));
}


// Query callback representing the query of a chaincode
func (t *SimpleChaincode) query(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    //logger.Info("########### example_cc0 query ###########")

    var etxKey string // Entities
    var err error

    if len(args) != 1 {
        return shim.Error("Incorrect number of arguments. Expecting name of the person to query")
    }

    etxKey = args[0]

    // Get the etx state from the ledger
    etxAsBytes, err := stub.GetState(etxKey)
    if err != nil {
        jsonResp := "{\"Error\":\"Failed to get state for " + etxKey + "\"}"
        return shim.Error(jsonResp)
    }

    if etxAsBytes == nil {
        return shim.Error("Failed to get state of a transcation" + etxKey)
    }

     // Construct the struct etx
    etx := EncryptedTransaction{}
    _ = json.Unmarshal(etxAsBytes, &etx)

    return shim.Success(etxAsBytes)
}

func (t *SimpleChaincode) addProofofAssets(stub shim.ChaincodeStubInterface, args []string) pb.Response {
    //logger.Info("########### example_cc0 addProofofAssets ###########")


    pkiJson := `{"PK": [
    {"X": 31162737974914322510223911493259949908325790533701417645370598536038546760813,"Y": 3243957534678192772627433866145815496382252068439063004526717165758982279478}, 
    {"X": 104306669726597258552457800704291913924157442819741684968539853652305339195302,"Y": 59723646933547178320805231501800256566404530244961528445232623018526217031402}, 
    {"X": 78990978055875482213519426577566655084235914353126259846189426580585978191425,"Y": 14838356030615363985994465553279457831477711117352611982834955835709977276603}, 
    {"X": 60284213037711622963860348272688379503451660376614053888286834031195565953917,"Y": 31555205998050805369326328704358754043154607628971344387956391519812942635882}, 
    {"X": 104597657332180700732862897786513766669655094268388302589461598923822453112374,"Y": 51659256023242095536989650590244254087257334458253939072448084726506084032326}]}` 

    var pki PKI 
    json.Unmarshal([]byte(pkiJson), &pki)

    ZKLedgerCurveKey := "ZKLedgerCurveKey"
    var err error
    
    // Check if the invoke request has exactly 1 arg
    // should have 3 args for 4 banks
    // if len(args) != 3 {
    //     return shim.Error("Incorrect number of arguments. Expecting 3, function followed by 2 names and 1 value")
    // }

    // should have 6 args (3 etx + 3 cachelist) for 4 banks
    // now i change all banks to have a batch of 10 proof of a
    // should have 20 args (10 etx + 10 cachelist) 
    if len(args) != 20 {
        return shim.Error("Incorrect number of arguments. Expecting 3, function followed by 2 names and 1 value")
    }
   
    // move the zkledger curve up

    // Get the ZKLedgerCurve state from the ledger
    ZKLedgerCurveAsBytes, err := stub.GetState(ZKLedgerCurveKey)
    if err != nil {
        jsonResp := "{\"Error\":\"Failed to get state for ZKLedgerCurve\"}"
        return shim.Error(jsonResp)
    }
    if ZKLedgerCurveAsBytes == nil {
        return shim.Error("Failed to get state of ZKLedgerCurve")
    }

    //Construct the struct ZKLedgerCurve

    // init 
    s256 := sha256.New()

    // // This was changed in ZKSigma, but keys already generated part of the repo
    // // should still work. So reverted this to what was originally in ZKLedger,

    // see:
    // hashedString := s256.Sum([]byte("This is the new random point in zksigma"))
    // HX, HY := btcec.S256().ScalarMult(btcec.S256().Gx, btcec.S256().Gy, hashedString)
    curValue := btcec.S256().Gx
    s256.Write(new(big.Int).Add(curValue, big.NewInt(2)).Bytes()) // hash G_x + 2 which

    potentialXValue := make([]byte, 33)
    binary.LittleEndian.PutUint32(potentialXValue, 2)
    for i, elem := range s256.Sum(nil) {
        potentialXValue[i+1] = elem
    }

    H, err := btcec.ParsePubKey(potentialXValue, btcec.S256())
    if err != nil {
        panic(err)
    }
    ZKLedgerCurve = zksigma.ZKPCurveParams{
        C: btcec.S256(),
        G: zksigma.ECPoint{btcec.S256().Gx, btcec.S256().Gy},
        H: zksigma.ECPoint{H.X, H.Y},
    }
    ZKLedgerCurve.HPoints = generateH2tothe()
    
    _ = json.Unmarshal(ZKLedgerCurveAsBytes, &ZKLedgerCurve)

    var etxtmp EncryptedTransaction 
    //size = *numbanks - 1
    var etx [10] EncryptedTransaction
    j :=0
    for i :=0; i < 19; i = i+ 2{
        etxJson := args[i]
        if etxJson == "" {
            return shim.Error("etxJson not found")
        }
        json.Unmarshal([]byte(etxJson), &etx[j])
        etxKey := "etx" + strconv.Itoa(etx[j].Index)
    
        var CacheList CacheListStruct
        CacheListJson := args[i + 1]
        if CacheListJson == "" {
            return shim.Error("etxJson not found")
        }
        json.Unmarshal([]byte(CacheListJson), &CacheList)

        CacheListKey := "CacheList" + strconv.Itoa(etx[j].Index)
        CommCache :=  CacheList.CommsCache
        RTokenCache := CacheList.RTokenCache

        startVerifyPoA := time.Now()
         if !etx[j].VerifyProofofAssets(pki.PK, CommCache, RTokenCache, fmt.Sprintf("%d", Id)) {
                return shim.Error("Proof of Assets does not verify!!! etx " + etxKey)
        }
        elapsedVerifyPoA := time.Since(startVerifyPoA)
        logger.Info("PoA Verify took %s", elapsedVerifyPoA)
         
        etxAsJSONBytes, _ := json.Marshal(etxtmp)

        // Write the state back to the ledger
        err = stub.PutState(etxKey, []byte(etxAsJSONBytes))
        if err != nil {
            return shim.Error("Failed to update Proof of Asset " + etxKey)
        }

        CacheList = CacheListStruct{CommsCache: CommsCache, RTokenCache: RTokenCache}
        CacheListAsJSONBytes, _ := json.Marshal(CacheList)

        err = stub.PutState(CacheListKey, []byte(CacheListAsJSONBytes))
        if err != nil {
            return shim.Error("Failed to write cache list " + CacheListKey)
        }

        j = j + 1

    }

    return shim.Success([]byte("Proof of Asset Updated."));
}

func generateH2tothe() []zksigma.ECPoint {
    Hslice := make([]zksigma.ECPoint, 64)
    for i := range Hslice {
        m := big.NewInt(1 << uint(i))
        Hslice[i].X, Hslice[i].Y = ZKLedgerCurve.C.ScalarBaseMult(m.Bytes())
    }
    return Hslice
}

func (en *Entry) verify(pks []zksigma.ECPoint, eidx int, i int, debug string) bool {

    // Check consistency proofs
    ok, err := en.CommConsistency.Verify(ZKLedgerCurve, en.Comm, en.RToken, pks[i])
    if !ok {
        Dprintf(" [%v] ETX %v Failed verify consistency comm entry %v %#v\n", debug, eidx, i, en)
        Dprintf("  [%v] %s", debug, err.Error())
        return false
    }
  
    return true
}

func (e *EncryptedTransaction) VerifyProofofAssets(pks []zksigma.ECPoint, CommCache []zksigma.ECPoint, RTokenCache []zksigma.ECPoint, debug string) bool {

    for i := 0; i < len(e.Entries); i++ {
        en := &e.Entries[i]
        if en.Bank != i {
            Dprintf(" [%v] ETX %v Failed verify mismatching bank %#v\n", debug, e.Index, en)
            return false
        }
        if !en.verifyProofofAssets(pks, CommCache[i], RTokenCache[i], e.Index, i, debug) {
            return false
        }  
    }
    
    return true
}

func (en *Entry) verifyProofofAssets(pks []zksigma.ECPoint, CommCache zksigma.ECPoint, RTokenCache zksigma.ECPoint, eidx int, i int, debug string) bool {
   
    // Check Aux consistency proofs
    ok, err := en.AuxConsistency.Verify(ZKLedgerCurve, en.CommAux, en.BAux, pks[i])
    if !ok {
        logger.Info("Failed verify AuxConsistency")
        Dprintf(" [%v] ETX %v Failed verify consistency aux entry %v\n", debug, eidx, i)
        Dprintf("  [%v] %s", debug, err.Error())
        return false
    }

    // Check Proof of Assets
    Base1 := ZKLedgerCurve.Add(en.CommAux, ZKLedgerCurve.Neg(CommCache))
    Result1 := ZKLedgerCurve.Add(en.BAux, ZKLedgerCurve.Neg(RTokenCache))
    Result2 := ZKLedgerCurve.Add(en.CommAux, ZKLedgerCurve.Neg(en.Comm))
    ok, err = en.Assets.Verify(ZKLedgerCurve, Base1, Result1, ZKLedgerCurve.H, Result2)
    if !ok {
        logger.Info("Failed Proof of Assets")
        logger.Info("Base1", Base1)
        logger.Info("Result1", Result1)
        logger.Info("Result2", Result2)
        fmt.Printf("  [%v] %v/%v Base1: %v\n", debug, eidx, i, Base1)
        fmt.Printf("  [%v] %v/%v Result1: %v\n", debug, eidx, i, Result1)
        fmt.Printf("  [%v] %v/%v Result2: %v\n", debug, eidx, i, Result2)
        fmt.Printf("  [%v] ETX %v Failed verify left side of proof of assets entry %v\n", debug, eidx, i)
        fmt.Printf("  [%v] %s", debug, err.Error())
        return false
    } 
    //   Range Proof
    ok, err = en.RP.Verify(ZKLedgerCurve, en.CommAux)
    if !ok {
        logger.Info("Failed Range Proof")
        Dprintf("  [%v] %v/%v Range Proof: %v\n", debug, eidx, i, en.RP)
        Dprintf("  [%v] ETX %v Failed verify the range proof on CommAux %v\n", debug, eidx, i)
        Dprintf("  [%v] %s", debug, err.Error())
        return false
    }
    
    return true
}

func (e *EncryptedTransaction) Verify(pks []zksigma.ECPoint, debug string) bool {

    //logger.Info("\n-----Verifing-----\n")


    // Issuance 
    if e.Type == Issuance {
        fmt.Println("\n  Issuance \n \n")
        en := &e.Entries[e.Sender]
        if en.V.Cmp(big.NewInt(0)) <= 0 {
            Dprintf(" [%v] ETX %v Failed verify; issuance transaction values must be positive\n",
                debug, e.Index)
            return false
        }
        // Check proof of knowledge of sk_{asset issuer}
        ok := false
        if en.SKProof != nil {
            // TODO: Error handling
            ok, _ = en.SKProof.Verify(ZKLedgerCurve, pks[len(pks)-1])
        }
        if !ok {
            Dprintf("[%v] ETX %v Failed issuance: proof of knowledge of SK\n", debug, e.Index)
            return false
        }
        return true
    }

    // Withdrawal
    if e.Type == Withdrawal {
        fmt.Println("\n  Withdrawal \n \n")
        en := &e.Entries[e.Sender]
        if en.V.Cmp(big.NewInt(0)) > 0 {
            Dprintf(" [%v] ETX %v Failed verify; withdrawal transaction values must be negative\n",
                debug, e.Index)
            return false
        }
        // Check proof of knowledge of sk_{bank}
        // TODO: Error handling
        ok, _ := en.SKProof.Verify(ZKLedgerCurve, pks[e.Sender])
        if !ok {
            Dprintf(" [%v] ETX %v Failed withdrawal: proof of knowledge of SK\n", debug, e.Index)
            return false
        }
        return true
    }

    // Transfer
    if (len(pks) - 1) != len(e.Entries) { // we subtract 1 from len(pks) because the last entry is the issuer's key
        fmt.Printf("Length pks: %v, length entries: %v\n", len(pks)-1, len(e.Entries))
        panic("invalid sizes")
    }
    commitmentSum := zksigma.Zero
    
    for i := 0; i < len(e.Entries); i++ {
        en := &e.Entries[i]
        commitmentSum = ZKLedgerCurve.Add(commitmentSum, en.Comm)
        if en.Bank != i {
            Dprintf(" [%v] ETX %v Failed verify mismatching bank %#v\n", debug, e.Index, en)
            return false
        }
        if !en.verify(pks, e.Index, i, debug) {
            return false
        }  
    }
    
    // to verify the zero sum commitments we add up all the values and make sure it adds to 0
    if commitmentSum.X.Cmp(new(big.Int).SetInt64(0)) != 0 && commitmentSum.Y.Cmp(new(big.Int).SetInt64(0)) != 0 {
        Dprintf(" [%v] ETX %v Failed verify zero sum\n", debug, e.Index)
        return false
    }

    return true
}

func Dprintf(format string, args ...interface{}) {
        fmt.Printf(format, args...)
}

func main() {
    logger.SetLevel(shim.LogInfo)
    // Start chaincode process
    err := shim.Start(new(SimpleChaincode))
    if err != nil {
        logger.Errorf("Error starting Simple chaincode: %s", err)
    }


}