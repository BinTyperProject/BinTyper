#include "pin.H"
#include <iostream>
#include <fstream>
#include <map>
#include "ClassInfoStructures.h"
#include "InstTypeInfo.h"
#include <sys/time.h>
#include "json.h"
#include <time.h>

uint64_t Now() {
    struct timeval tp;
    gettimeofday(&tp, NULL);
    long int ms = tp.tv_sec * 1000 + tp.tv_usec / 1000;
    return ms;
}

using namespace std;
using std::cerr;
using std::string;
using std::endl;

#define WRAP_FILE_IO_ARG(ARG) (char*)(&ARG), sizeof(ARG)

string TARGET_NAME;
string FILENAME_VFT_SET = "";
string SUFFIX_VFT_SET = ".vft_set";
string FILENAME_AREA_LAYOUT_INFORMATION = "";
string SUFFIX_AREA_LAYOUT_INFORMATION = ".output_identifier_with_area_layouts";
string FILENAME_TYPED_INSTRUCTION_INFORMATION = "";
string SUFFIX_TYPED_INSTRUCTION_INFORMATION = ".typed_instruction_information";

string TOOL_MODE_TRACK = "track";
string TOOL_MODE_VERIFY = "verify";

static string MODE = TOOL_MODE_TRACK;

template< typename T >
class range
{
public:
    typedef T value_type;

    range( T const & center ) : min_( center ), max_( center ) {}
    range( T const & min, T const & max )
        : min_( min ), max_( max ) {}
    T min() const { return min_; }
    T max() const { return max_; }
private:
    T min_;
    T max_;
};

template <typename T>
// struct left_of_range : public std::binary_function< range<T>, range<T>, bool >
struct left_of_range 
{
    bool operator()( range<T> const & lhs, range<T> const & rhs ) const
    {
        return lhs.min() < rhs.min()
            && lhs.max() <= rhs.min();
    }
};

template <typename T1, typename T2>
using RangeMap = std::map< range<T1>, T2, left_of_range<T1>>;

/* ================================================================== */
// Global variables 
/* ================================================================== */

std::ostream * out = &cerr;
std::ofstream f_typeinfo;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for output");
KNOB<string> KnobTargetName(KNOB_MODE_WRITEONCE,  "pintool",
    "i", "", "specify file name for target");
KNOB<string> KnobMode(KNOB_MODE_WRITEONCE,  "pintool",
    "m", "track", "specify mode");

///////////////////////////////////////////////////////////////////////////////////////////////////////////

static ADDRINT process_image_base;
static ADDRINT IMAGE_BASE; // Image base of exported analysis result
static RangeMap<ADDRINT /*range*/, ADDRINT /*base*/> active_mems;

/* JSON STRUCTURE:
{
    vft_set:
        [
            IDENTIFIER,
            IDENTIFIER,
            ...
        ]
}
*/
static set<ADDRINT> vft_set;

/* JSON STRUCTURE:
{
    TARGET_IDENTIFIER:
        {
            OFFSET: [SIZE, IDENTIFIER],
            OFFSET: [SIZE, IDENTIFIER],
            ...
        }
}
*/
static map<ADDRINT /*vft*/, RangeMap<ADDRINT /*range*/, ADDRINT /*VFT*/>> area_layout_information;

/* JSON STRUCTURE:
{
    TARGET_IDENTIFIER:
        {
            OPERATION_TYPE1:
                [ POSSIBLE_AREA_IDENTIFIER, POSSIBLE_AREA_IDENTIFIER ... ]
            OPERATION_TYPE2:
                [ POSSIBLE_AREA_IDENTIFIER, POSSIBLE_AREA_IDENTIFIER ... ]
            ...
        }
    ...
}
*/
static map<ADDRINT /*inst_addr*/, map<uint64_t /*type*/, set<ADDRINT> /*areas*/>> typed_instruction_info;

template<typename T>
std::string ToString(T value) {
    std::ostringstream oss;
    oss << value;
    return oss.str();
}


bool LoadVFTSet() {
    if (vft_set.size() != 0) return true; // already loaded

    ifstream f;
    std::string data;
    f.open(FILENAME_VFT_SET.c_str(), ios::in);
    if (!f) return false;
    ostringstream ss;
    ss << f.rdbuf();
    data = ss.str();

    auto obj = json::jobject::parse(data);
    std::vector<ADDRINT> vft_vector = obj["vft_set"];

    vft_set.insert(vft_vector.begin(), vft_vector.end());
    return true;
}

bool LoadAreaLayoutInformation() {
    if (area_layout_information.size() != 0) return true; // already loaded

    ifstream f;
    std::string data;
    f.open(FILENAME_AREA_LAYOUT_INFORMATION.c_str(), ios::in | ios::binary);
    if (!f) return false;
    ostringstream ss;
    ss << f.rdbuf();
    data = ss.str();

    auto obj = json::jobject::parse(data);
    for (auto it_obj : obj.data) {
        RangeMap<ADDRINT /*range*/, ADDRINT /*VFT*/> internal_area_layout;
        auto target_identifier = it_obj.first;
        auto area_layout_json = obj[target_identifier].as_object();
        for (auto it_area_layout : area_layout_json.data) {
            auto offset = it_area_layout.first;
            std::vector<ADDRINT> area_info = area_layout_json[offset];
            auto size = area_info[0];
            auto area_identifier = area_info[1];

            auto offset_int = json::parsing::get_number<ADDRINT>(offset.c_str(), "%llu");
            internal_area_layout[range<ADDRINT>(offset_int, offset_int+size)] = area_identifier;
        } 
        area_layout_information[json::parsing::get_number<ADDRINT>(target_identifier.c_str(), "%llu")] = internal_area_layout;
    }
    return true;
}

bool LoadTypedInstructionInfo() {
    if (typed_instruction_info.size() != 0) return true; // already loaded

    ifstream f;
    std::string data;
    f.open(FILENAME_TYPED_INSTRUCTION_INFORMATION.c_str(), ios::in | ios::binary);
    if (!f) return false;
    ostringstream ss;
    ss << f.rdbuf();
    data = ss.str();

    auto obj = json::jobject::parse(data);
    for (auto it_obj : obj.data) {
        auto target_identifier = it_obj.first;
        auto area_map_json = obj[target_identifier].as_object();
        std::map<ADDRINT, std::set<ADDRINT>> area_map;
        for (auto it_area_map : area_map_json.data) {
            auto operation_type = it_area_map.first;
            std::vector<ADDRINT> possible_areas = area_map_json[operation_type];
            std::set<ADDRINT> set_areas(possible_areas.begin(), possible_areas.end());
            area_map[json::parsing::get_number<ADDRINT>(operation_type.c_str(), "%llu")] = set_areas;
        }
        typed_instruction_info[json::parsing::get_number<ADDRINT>(target_identifier.c_str(), "%llu")] = area_map;
    }

    return true;
}

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

// static uint64_t graph_x = 0;
// vector<uint64_t> graph_ys;
// static uint64_t object_count=0;

void ExamineAccessedArea(UINT64 ins_ea, UINT64 mem_addr, UINT32 size, AccessType access_type) {
    // graph_x += 1;
    // if (graph_x >= 1000) {
    //     graph_ys.push_back(object_count);
    //     graph_x = 0;
    // }

    // [TRACKING/VERIFICATION] Load VFT Set
    bool load_vftset = LoadVFTSet();
    if (!load_vftset) {
        *out << "Error on load vft set" << endl;
        exit(1);
    }

    if (MODE == TOOL_MODE_VERIFY) {
        // [VERIFICATION] Check whether access is occured in typed-instruction
        bool load_typed_inst_info = LoadTypedInstructionInfo();
        if (!load_typed_inst_info) {
            *out << "Error on load typed instruction information" << endl;
            exit(1);
        }
        auto inst_result = typed_instruction_info.find(ins_ea - process_image_base /*rva*/);
        if (inst_result == typed_instruction_info.end()) return;
    } else if (MODE == TOOL_MODE_TRACK) {
        // [TRACKING] Load previously-logged typed instruction information
        LoadTypedInstructionInfo(); // Load previously logged typed-insturction information
    }

    // [TRACKING/VERIFICATION] Check whether accessed memory is active malloc-ed memory
    auto active_mems_result = active_mems.find(range<ADDRINT>(mem_addr));
    if (active_mems_result == active_mems.end()) return;

    // [TRACKING/VERIFICATION] Check whether accessed memory points possible vft
    ADDRINT ref_vft = (*active_mems_result).second;
    auto offset = mem_addr - ref_vft;
    ADDRINT vft = *(ADDRINT*)ref_vft - process_image_base;
    auto vft_result = vft_set.find(vft);
    // *out << (void*)vft << "\n";
    if (vft_result == vft_set.end()) return;
    // *out << "VFT ACCESS : " << (void*)vft << endl;

    // [TRACKING/VERIFICATION] Resolve accessed area with area layout information
    bool load_arealayoutinformation = LoadAreaLayoutInformation();
    if (!load_arealayoutinformation) {
        *out << "Error on load area layout information" << endl;
        exit(1);
    }
    auto area_layout_result = area_layout_information.find(vft-16);
    if (area_layout_result == area_layout_information.end()) return;
    auto area_layout = (*area_layout_result).second;
    auto sub_area_result = area_layout.find(offset);
    // *out << "OFFSET : " << (void*)offset << endl;
    if (sub_area_result == area_layout.end()) return;
    // *out << "OFFSET SUCCESS" << endl;
    auto sub_area = (*sub_area_result).second;
    // *out << "HELLO " << (void*)sub_area << endl;

    if (MODE == TOOL_MODE_TRACK) {
        // [TRACKING] Save resolved area
        typed_instruction_info[ins_ea - process_image_base /*rva*/][access_type].insert(sub_area);
    } else if (MODE == TOOL_MODE_VERIFY) {
        // [VERIFICATION] Check matches among areas
        auto inst_result = typed_instruction_info.find(ins_ea - process_image_base /*rva*/);
        auto wanna_areas = ((*inst_result).second)[access_type];
        if (wanna_areas.find(sub_area) == wanna_areas.end()) { 
            // Actual area isn't included in possible areas
            // It means type-confusion
            *out << "[+] Type confusion detected" << endl;
            *out << "RVA : " << (void*)(ins_ea - process_image_base) << endl;
            *out << "Actual accessed area : " << (void*)(sub_area) << endl;
            *out << "Required areas :";
            for(auto wanna_area : wanna_areas) {
                *out << " " << (void*)wanna_area;
            }
            *out << endl;
        }
    }
}

VOID Instruction(INS ins, VOID *v)
{
    ADDRINT addr = INS_Address(ins);
    // We should convert addr to rva
    IMG img = IMG_FindByAddress(addr);
    if (img == IMG_Invalid()) {
        return;
    }
    string image_path = IMG_Name(img);
    string image_name;
    auto pos = image_path.rfind("/");
    if (pos != string::npos) {
        image_name = image_path.substr(pos + 1);
    } else {
        image_name = image_path;
    }

    if (image_name != TARGET_NAME) {
        return;
    }
    process_image_base = IMG_LowAddress(img);
    assert(addr >= process_image_base);
    // ADDRINT rva = addr - process_image_base;

    // Observe meomry access
    // Memroy read 1
    if (INS_IsMemoryRead(ins) && !INS_IsStackRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ExamineAccessedArea,
                       IARG_INST_PTR,
                       IARG_MEMORYREAD_EA,
                       IARG_MEMORYREAD_SIZE,
                       IARG_UINT64, ACCESS_READ1,
                       IARG_END);
    }
    if (INS_HasMemoryRead2(ins) && !INS_IsStackRead(ins)) {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ExamineAccessedArea,
                       IARG_INST_PTR,
                       IARG_MEMORYREAD2_EA,
                       IARG_MEMORYREAD_SIZE,
                       IARG_UINT64, ACCESS_READ2,
                       IARG_END);
    }
    if (INS_IsMemoryWrite(ins) && !INS_IsStackWrite(ins)) { 
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ExamineAccessedArea,
                       IARG_INST_PTR,
                       IARG_MEMORYWRITE_EA,
                       IARG_MEMORYWRITE_SIZE,
                       IARG_UINT64, ACCESS_WRITE,
                       IARG_END);
    }
}

static map<THREADID, uint64_t> latest_malloc_size;

VOID TrackMallocBefore(THREADID tid, uint64_t size) {
    // *out << "ALLOC " << (void*)addr << " + " << (void*)size << endl;
    // active_mems[range<ADDRINT>(addr, addr+size)] = addr;
    latest_malloc_size[tid] = size;
}

VOID TrackMallocAfter(THREADID tid, ADDRINT addr) {
    assert(latest_malloc_size.find(tid) != latest_malloc_size.end());
    auto result = latest_malloc_size.find(tid);
    auto size = (*result).second;
    // *out << "ALLOC " << (void*)addr << " + " << (void*)size << endl;
    active_mems[range<ADDRINT>(addr, addr+size)] = addr;
    latest_malloc_size.erase(tid);
    // object_count += 1;
}

VOID TrackFree(ADDRINT addr) {
    auto result = active_mems.find(range<ADDRINT>(addr));
    if (result == active_mems.end()) return;
    // *out << "FREE " << (void*)((*result).second) << endl;
    active_mems.erase(result);
    // if (object_count < 5) {
    //     object_count = 0;
    // } else {
    //     object_count -= 1;
    // }
}

VOID InstrumentMallocFree(IMG img, VOID *v) {
    RTN rtn_free = RTN_FindByName(img, "free");
    if (rtn_free.is_valid()) {
        RTN_Open(rtn_free);
        RTN_InsertCall(rtn_free, IPOINT_BEFORE, (AFUNPTR)TrackFree,
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(rtn_free);
    }
    RTN rtn_malloc = RTN_FindByName(img, "malloc");
    if (rtn_malloc.is_valid()) {
        RTN_Open(rtn_malloc);
        RTN_InsertCall(rtn_malloc, IPOINT_BEFORE, (AFUNPTR)TrackMallocBefore,
                       IARG_THREAD_ID, 	
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(rtn_malloc, IPOINT_AFTER, (AFUNPTR)TrackMallocAfter,
                       IARG_THREAD_ID, 	
                       IARG_FUNCRET_EXITPOINT_VALUE,
                       IARG_END);
        RTN_Close(rtn_malloc);
    }
}

VOID ThreadStart(THREADID threadIndex, CONTEXT *ctxt, INT32 flags, VOID *v)
{
}

VOID Fini(INT32 code, VOID *v)
{
    if (MODE == TOOL_MODE_TRACK) {
        std::ofstream f_typedinstinfo;
        // Export typed_instruction_info to file
        f_typedinstinfo.open(FILENAME_TYPED_INSTRUCTION_INFORMATION.c_str(), ios::out | ios::binary);

        json::jobject result;
        for (auto it_typed_instruction_info : typed_instruction_info) {
            auto target_identifier = it_typed_instruction_info.first;
            auto sub_area_map = it_typed_instruction_info.second;
            json::jobject possible_area_map;
            for (auto it_sub_area_map : sub_area_map) {
                auto operation_type = it_sub_area_map.first;
                auto possible_areas = it_sub_area_map.second;
                std::vector<ADDRINT> possible_areas_vector;
                possible_areas_vector.assign(possible_areas.begin(), possible_areas.end());

                possible_area_map[ToString(operation_type)] = possible_areas_vector;
            }
            result[ToString(target_identifier)] = possible_area_map;
        }
        // f_typedinstinfo.write(result.as_string());
        f_typedinstinfo << result.as_string();
        f_typedinstinfo.close();
    }

    *out <<  "== END ==" << endl;

    // Time metric
    // std::ofstream f_metric;
    // f_metric.open("performance", ios::out);
    // for (uint64_t i=0; i<graph_ys.size(); i++) {
    //     f_metric << i*1000 << " " << graph_ys[i]-graph_ys[0] << endl;
    // }
}

int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    PIN_InitSymbols();
    
    string fileName = KnobOutputFile.Value();
    TARGET_NAME = KnobTargetName.Value();
    MODE = KnobMode.Value();

    FILENAME_VFT_SET = TARGET_NAME + SUFFIX_VFT_SET + ".bintyper.json";
    FILENAME_AREA_LAYOUT_INFORMATION = TARGET_NAME + SUFFIX_AREA_LAYOUT_INFORMATION + ".bintyper.json";
    FILENAME_TYPED_INSTRUCTION_INFORMATION = TARGET_NAME + SUFFIX_TYPED_INSTRUCTION_INFORMATION + ".bintyper.json";

    IMAGE_BASE = 0;

    if (!fileName.empty()) { 
        time_t rawtime;
        struct tm * timeinfo;
        char buffer[100];
        time(&rawtime);
        timeinfo = localtime(&rawtime);
        strftime(buffer, sizeof(buffer), "%F_%H-%M-%S", timeinfo);
        // cerr << buffer << endl;
        auto pid = PIN_GetPid();
        string output_name;
        string formatted_time = buffer;
        output_name = fileName + "_" + formatted_time + "_" + ToString(pid);
        out = new std::ofstream(output_name.c_str());
    }

    // Register function to track malloc/free
    IMG_AddInstrumentFunction(InstrumentMallocFree, 0);

    // Register function to be called to instrument traces
    INS_AddInstrumentFunction(Instruction, 0);

    // Register function to be called for every thread before it starts running
    PIN_AddThreadStartFunction(ThreadStart, 0);

    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);
    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by BinTyperTracker" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        string mode_string = "INVALID";
        if (MODE == TOOL_MODE_TRACK) {
            mode_string = "TRACK";
        } else if (MODE == TOOL_MODE_VERIFY) {
            mode_string = "VERIFY";
        }
        cerr << "CURRENT MODE: " << mode_string << endl;;
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
