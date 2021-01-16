#ifndef JSON_H
#define JSON_H

#include <string>
#include <vector>
#include <cstdio>
#include <utility>
#include <stdexcept>
#include <cctype>

#define NUMBER_TO_STRING_BUFFER_LENGTH 100

namespace json
{
	class invalid_key : public std::exception
	{
	public:
		const std::string key;
		inline invalid_key(const std::string &key) : key(key) { }
		inline virtual ~invalid_key() throw() { }
		virtual const char* what() const throw()
		{
			return key.c_str();
		}
	};

	class parsing_error : public std::invalid_argument
	{
	public:
		inline parsing_error(const char *message) : std::invalid_argument(message) { }
		inline virtual ~parsing_error() throw() { }
	};

	namespace parsing
	{
		const char* tlws(const char *start);
	}

	/* Data types */
	namespace jtype
	{
		enum jtype { jstring, jnumber, jobject, jarray, jbool, jnull, not_valid };
		jtype detect(const char *input);
	}

	namespace parsing
	{
		std::string read_digits(const char *input);
		std::string escape_quotes(const char *input);
		std::string unescape_quotes(const char *input);

		struct parse_results
		{
			jtype::jtype type;
			std::string value;
			const char *remainder;
		};

		parse_results parse(const char *input);
		
		template <typename T>
		T get_number(const char *input, const char* format)
		{
			T result;
			std::sscanf(input, format, &result);
			return result;
		}

		template <typename T>
		std::string get_number_string(const T &number, const char *format)
		{
			char cstr[NUMBER_TO_STRING_BUFFER_LENGTH];
			std::sprintf(cstr, format, number);
			return std::string(cstr);
		}

		std::vector<std::string> parse_array(const char *input);
	}

	typedef std::pair<std::string, std::string> kvp;

	class jobject
	{
	private:

		class const_proxy
		{
		private:
			const jobject &source;
		protected:
			const std::string key;
			template<typename T>
			inline T get_number(const char* format) const
			{
				return json::parsing::get_number<T>(this->source.get(key).c_str(), format);
			}
			template<typename T>
			inline std::vector<T> get_number_array(const char* format) const
			{
				std::string value = this->source.get(key);
				std::vector<std::string> numbers = json::parsing::parse_array(value.c_str());
				std::vector<T> result;
				for (size_t i = 0; i < numbers.size(); i++)
				{
					result.push_back(json::parsing::get_number<T>(numbers[i].c_str(), format));
				}
				return result;
			}
		public:
			const_proxy(const jobject &source, const std::string key) : source(source), key(key) { }

			inline std::string as_string() const
			{
				const std::string value = source.get(key);
				return json::parsing::unescape_quotes(json::parsing::parse(value.c_str()).value.c_str());
			}

			inline operator std::string() const 
			{
				return this->as_string();
			}

			bool operator== (const std::string other) const { return ((std::string)(*this)) == other; }
			bool operator!= (const std::string other) const { return !(((std::string)(*this)) == other); }

			// Numbers
			operator int() const { return this->get_number<int>("%i"); }
			operator unsigned int() const { return this->get_number<unsigned int>("%u"); }
			operator long() const { return this->get_number<long>("%li"); }
			operator unsigned long() const { return this->get_number<unsigned long>("%lu"); }
			operator char() const { return this->get_number<char>("%c"); }
			operator float() const { return this->get_number<float>("%f"); }
			operator double() const { return this->get_number<double>("%lf"); }

			// Objects
			inline json::jobject as_object() const
			{
				const std::string value = this->source.get(key);
				return json::jobject::parse(value.c_str());
			}

			inline operator json::jobject() const
			{
				return this->as_object();
			}

			// Arrays
			operator std::vector<int>() const { return this->get_number_array<int>("%i"); }
			operator std::vector<unsigned int>() const { return this->get_number_array<unsigned int>("%u"); }
			operator std::vector<long>() const { return this->get_number_array<long>("%li"); }
			operator std::vector<unsigned long>() const { return this->get_number_array<unsigned long>("%lu"); }
			operator std::vector<char>() const { return this->get_number_array<char>("%c"); }
			operator std::vector<float>() const { return this->get_number_array<float>("%f"); }
			operator std::vector<double>() const { return this->get_number_array<double>("%f"); }
			operator std::vector<json::jobject>() const
			{
				const std::vector<std::string> objs = json::parsing::parse_array(this->source.get(key).c_str());
				std::vector<json::jobject> results;
				for (size_t i = 0; i < objs.size(); i++) results.push_back(json::jobject::parse(objs[i].c_str()));
				return results;
			}
			operator std::vector<std::string>() const { return json::parsing::parse_array(this->source.get(key).c_str()); }

			template<typename T>
			inline std::vector<T> as_array() const
			{
				return (std::vector<T>)(*this);
			}

			// Boolean
			inline bool is_true() const
			{
				const std::string value = this->source.get(key);
				json::parsing::parse_results result = json::parsing::parse(value.c_str());
				return (result.type == json::jtype::jbool && result.value == "true");
			}

			// Null
			inline bool is_null() const
			{
				const std::string value = this->source.get(key);
				json::parsing::parse_results result = json::parsing::parse(value.c_str());
				return result.type == json::jtype::jnull;
			}
		};

		class proxy : public json::jobject::const_proxy
		{
			jobject &sink;
		protected:
			template<typename T>
			inline void set_number(const T value, const char* format)
			{
				this->sink.set(key, json::parsing::get_number_string(value, format));
			}

			void set_array(const std::vector<std::string> &values, const bool wrap = false);

			template<typename T>
			inline void set_number_array(const std::vector<T> &values, const char* format)
			{
				std::vector<std::string> numbers;
				for (size_t i = 0; i < values.size(); i++)
				{
					numbers.push_back(json::parsing::get_number_string(values[i], format));
				}
				this->set_array(numbers);
			}
		public:
			proxy(jobject &source, const std::string key) 
				: json::jobject::const_proxy(source, key),
				sink(source)
			{ }

			// Strings
			inline void operator= (const std::string value)
			{
				this->sink.set(this->key, "\"" + json::parsing::escape_quotes(value.c_str()) + "\"");
			}

			// Numbers
			void operator=(const int input) { this->set_number(input, "%i"); }
			void operator=(const unsigned int input) { this->set_number(input, "%u"); }
			void operator=(const long input) { this->set_number(input, "%li"); }
			void operator=(const unsigned long input) { this->set_number(input, "%lu"); }
			void operator=(const char input) { this->set_number(input, "%c"); }
			void operator=(const double input) { this->set_number(input, "%e"); }
			void operator=(const float input) { this->set_number(input, "%e"); }

			// Objects
			void operator=(json::jobject input)
			{
				this->sink.set(key, (std::string)input);
			}

			// Arrays
			void operator=(const std::vector<int> input) { this->set_number_array(input, "%i"); }
			void operator=(const std::vector<unsigned int> input) { this->set_number_array(input, "%u"); }
			void operator=(const std::vector<long> input) { this->set_number_array(input, "%li"); }
			void operator=(const std::vector<unsigned long> input) { this->set_number_array(input, "%lu"); }
			void operator=(const std::vector<char> input) { this->set_number_array(input, "%c"); }
			void operator=(const std::vector<float> input) { this->set_number_array(input, "%e"); }
			void operator=(const std::vector<double> input) { this->set_number_array(input, "%e"); }
			void operator=(const std::vector<std::string> input) { this->set_array(input, true); }
			void operator=(std::vector<json::jobject> input)
			{
				std::vector<std::string> objs;
				for (size_t i = 0; i < input.size(); i++)
				{
					objs.push_back((std::string)input[i]);
				}
				this->set_array(objs, false);
			}

			// Boolean
			inline void set_boolean(const bool value)
			{
				if (value) this->sink.set(key, "true");
				else this->sink.set(key, "false");
			}

			// Null
			inline void set_null()
			{
				this->sink.set(key, "null");
			}

			inline void clear()
			{
				this->sink.remove(key);
			}
		};
	public:
		std::vector<kvp> data;
		inline jobject() { }
		inline virtual ~jobject() { }

		inline size_t size() const { return this->data.size(); }

		inline void clear() { this->data.resize(0); }

		jobject& operator+=(const kvp& other)
		{
			if (this->has_key(other.first)) { int *a = 0; *a = 1; }
			this->data.push_back(other);
			return *this;
		}

		jobject& operator+=(jobject& other)
		{
			for (size_t i = 0; i < other.size(); i++) this->data.push_back(other.data.at(i));
			return *this;
		}

		jobject& operator+=(const jobject& other)
		{
			json::jobject copy(other);
			for (size_t i = 0; i < copy.size(); i++) this->data.push_back(other.data.at(i));
			return *this;
		}

		jobject operator+(jobject& other)
		{
			jobject result = *this;
			result += other;
			return result;
		}

		static jobject parse(const char *input);
		static inline jobject parse(const std::string input) { return parse(input.c_str()); }

		// Returns true if a json parsing error occured
		inline bool static tryparse(const char *input, jobject &output)
		{
            output = parse(input);
			return false;
		}

		inline bool has_key(const std::string &key) const
		{
			for (size_t i = 0; i < this->size(); i++) if (this->data.at(i).first == key) return true;
			return false;
		}

		void set(const std::string &key, const std::string &value);

		inline std::string get(const std::string &key) const
		{
			for (size_t i = 0; i < this->size(); i++) if (this->data.at(i).first == key) return this->data.at(i).second;
			{ int *a = 0; *a = 1; }
            return "";
		}

		void remove(const std::string &key);

		inline virtual jobject::proxy operator[](const std::string key)
		{
			return jobject::proxy(*this, key);
		}

		inline virtual const jobject::const_proxy operator[](const std::string key) const
		{
			return jobject::const_proxy(*this, key);
		}

		operator std::string() const;

		inline std::string as_string() const
		{
			return this->operator std::string();
		}
	};
}

#endif // !JSON_H

#define EMPTY_STRING(str) (*str == '\0')
#define SKIP_WHITE_SPACE(str) { const char *next = json::parsing::tlws(str); str = next; }

const char* json::parsing::tlws(const char *input)
{
    const char *output = input;
    while(!EMPTY_STRING(output) && std::isspace(*output)) output++;
    return output;
}

json::jtype::jtype json::jtype::detect(const char *input)
{
    const char *start = json::parsing::tlws(input);
    if (EMPTY_STRING(start)) return json::jtype::not_valid;
    switch (*start)
    {
    case '[':
        return json::jtype::jarray;
        break;
    case '"':
        return json::jtype::jstring;
        break;
    case '{':
        return json::jtype::jobject;
        break;
    case '-':
    case '0':
    case '1':
    case '2':
    case '3':
    case '4':
    case '5':
    case '6':
    case '7':
    case '8':
    case '9':
        return json::jtype::jnumber;
    case 't':
    case 'f':
        return (strncmp(start, "true", 4) == 0 || strncmp(start, "false", 5) == 0) ? json::jtype::jbool : json::jtype::not_valid;
        break;
    case 'n':
        return (strncmp(start, "null", 4) == 0) ? json::jtype::jnull : json::jtype::not_valid;
        break;
    default:
        return json::jtype::not_valid;
        break;
    }
}

std::string json::parsing::read_digits(const char *input)
{
    // Trim leading white space
    const char *index = json::parsing::tlws(input);

    // Initialize the result
    std::string result;

    // Loop until all digits are read
    while (
        !EMPTY_STRING(index) &&
        (
            *index == '0' ||
            *index == '1' ||
            *index == '2' ||
            *index == '3' ||
            *index == '4' ||
            *index == '5' ||
            *index == '6' ||
            *index == '7' ||
            *index == '8' ||
            *index == '9'
            )
        )
    {
        result += *index;
        index++;
    }

    // Return the result
    return result;
}

std::string json::parsing::escape_quotes(const char *input)
{
    std::string parsed;
    const size_t len = strlen(input);
    for (size_t i = 0; i < len; i++)
    {
        if (input[i] == '\"' && parsed[parsed.size() - 1] != '\\')
        {
            parsed += '\\';
        }
        parsed += input[i];
    }
    return parsed;
}

std::string json::parsing::unescape_quotes(const char *input)
{
    std::string result;
    const char *index = input;
    while (!EMPTY_STRING(index))
    {
        if (strlen(index) > 1 && *index == '\\' && index[1] == '\"')
        {
            result += '\"';
            index += 2;
        }
        else
        {
            result.push_back(*index);
            index++;
        }
    }
    return result;
}

json::parsing::parse_results json::parsing::parse(const char *input)
{
    // Strip white space
    const char *index = json::parsing::tlws(input);

    // Validate input
    if (EMPTY_STRING(index)) { int *a = 0; *a = 1; }

    // Initialize the output
    json::parsing::parse_results result;

    // Detect the type
    result.type = json::jtype::detect(index);

    // Parse the values
    switch (result.type)
    {
    case json::jtype::jstring:
        // Validate the input
        if (*index != '"') { int *a = 0; *a = 1; }

        // Remove the opening quote
        index++;

        // Copy the string
        while (!EMPTY_STRING(index))
        {
            if (*index != '"' || (result.value.size() > 0 && result.value[result.value.size() - 1] == '\\'))
            {
                result.value.push_back(*index);
                index++;
            }
            else
            {
                break;
            }
        }
        if (EMPTY_STRING(index) || *index != '"') result.type = json::jtype::not_valid;
        else index++;
        break;
    case json::jtype::jnumber:
    {

        if (*index == '-')
        {
            result.value.push_back('-');
            index++;
        }

        if (EMPTY_STRING(index)) { int *a = 0; *a = 1; }

        // Read the whole digits
        std::string whole_digits = json::parsing::read_digits(index);

        // Validate the read
        if (whole_digits.length() == 0) { int *a = 0; *a = 1; }

        // Tack on the value
        result.value += whole_digits;
        index += whole_digits.length();

        // Check for decimal number
        if (*index == '.')
        {
            result.value.push_back('.');
            index++;
            std::string decimal_digits = json::parsing::read_digits(index);

            if (decimal_digits.length() == 0) { int *a = 0; *a = 1; }

            result.value += decimal_digits;
            index += decimal_digits.size();
        }

        // Check for exponential number
        if (*index == 'e' || *index == 'E')
        {
            result.value.push_back(*index);
            index++;

            if (EMPTY_STRING(index)) { int *a = 0; *a = 1; }

            if (*index == '+' || *index == '-')
            {
                result.value.push_back(*index);
                index++;
            }

            if (EMPTY_STRING(index)) { int *a = 0; *a = 1; }

            std::string exponential_digits = json::parsing::read_digits(index);

            if (exponential_digits.size() == 0) { int *a = 0; *a = 1; }

            result.value += exponential_digits;
            index += exponential_digits.size();
        }
        break;
    }
    case json::jtype::jobject:
    {

        // The first character should be an open bracket
        if (*index != '{') { int *a = 0; *a = 1; }
        result.value += '{';
        index++;
        SKIP_WHITE_SPACE(index);

        // Loop until the closing bracket is encountered
        while (!EMPTY_STRING(index) && *index != '}')
        {
            // Read the key
            json::parsing::parse_results key = json::parsing::parse(index);

            // Validate that the key is a string
            if (key.type != json::jtype::jstring) { int *a = 0; *a = 1; }

            // Store the key
            result.value += "\"" + json::parsing::escape_quotes(key.value.c_str()) + "\"";
            index = json::parsing::tlws(key.remainder);

            // Look for the colon
            if (*index != ':') { int *a = 0; *a = 1; }
            result.value.push_back(':');
            index++;

            // Get the value
            json::parsing::parse_results subvalue = json::parsing::parse(index);

            // Validate the value type
            if (subvalue.type == json::jtype::not_valid) { int *a = 0; *a = 1; }

            // Store the value
            if (subvalue.type == json::jtype::jstring) result.value += "\"" + json::parsing::escape_quotes(subvalue.value.c_str()) + "\"";
            else result.value += subvalue.value;
            index = json::parsing::tlws(subvalue.remainder);

            // Validate format
            if (*index != ',' && *index != '}') { int *a = 0; *a = 1; }

            // Check for next line
            if (*index == ',')
            {
                result.value.push_back(',');
                index++;
            }
        }
        if (*index != '}') { int *a = 0; *a = 1; }
        result.value += '}';
        index++;
        break;
    }
    case json::jtype::jarray:
    {
        if (*index != '[') { int *a = 0; *a = 1; }
        result.value += '[';
        index++;
        SKIP_WHITE_SPACE(index);
        if (EMPTY_STRING(index)) { int *a = 0; *a = 1; }
        while (!EMPTY_STRING(index) && *index != ']')
        {
            json::parsing::parse_results array_value = json::parsing::parse(index);
            if (array_value.type == json::jtype::not_valid) { int *a = 0; *a = 1; }
            if (array_value.type == json::jtype::jstring) result.value += "\"" + json::parsing::escape_quotes(array_value.value.c_str()) + "\"";
            else result.value += array_value.value;
            index = json::parsing::tlws(array_value.remainder);
            if (*index != ',' && *index != ']') { int *a = 0; *a = 1; }
            if (*index == ',')
            {
                result.value.push_back(',');
                index++;
            }
        }
        if (*index != ']') { int *a = 0; *a = 1; }
        result.value.push_back(']');
        index++;
        break;
    }
    case json::jtype::jbool:
    {
        if (strncmp(index, "true", 4) == 0)
        {
            result.value += "true";
            index += 4;
        }
        else if (strncmp(index, "false", 4) == 0)
        {
            result.value += "false";
            index += 5;
        }
        else
        {
            { int *a = 0; *a = 1; }
        }
        break;
    }
    case json::jtype::jnull:
    {
        if (strncmp(index, "null", 4) == 0)
        {
            result.value += "null";
            index+= 4;
        }
        else
        {
            { int *a = 0; *a = 1; }
        }
        break;
    }
    default:
        { int *a = 0; *a = 1; }
        break;
    }

    result.remainder = index;
    return result;
}

std::vector<std::string> json::parsing::parse_array(const char *input)
{
    // Initalize the result
    std::vector<std::string> result;

    const char *index = json::parsing::tlws(input);
    if (*index != '[') { int *a = 0; *a = 1; }
    index++;
    SKIP_WHITE_SPACE(index);
    if (*index == ']')
    {
        return result;
    }
    while (!EMPTY_STRING(index))
    {
        SKIP_WHITE_SPACE(index);
        json::parsing::parse_results parse_results = json::parsing::parse(index);
        if (parse_results.type == json::jtype::not_valid) { int *a = 0; *a = 1; }
        result.push_back(parse_results.value);
        index = json::parsing::tlws(parse_results.remainder);
        if (*index == ']') break;
        if (*index == ',') index++;
    }
    if (*index != ']') { int *a = 0; *a = 1; }
    index++;
    return result;
}

void json::jobject::proxy::set_array(const std::vector<std::string> &values, const bool wrap)
{
    std::string value = "[";
    for (size_t i = 0; i < values.size(); i++)
    {
        if (wrap) value += "\"" + json::parsing::escape_quotes(values[i].c_str()) + "\",";
        else value += values[i] + ",";
    }
    if(values.size() > 0) value.erase(value.size() - 1, 1);
    value += "]";
    this->sink.set(key, value);
}

json::jobject json::jobject::parse(const char *input)
{
    const char *index = json::parsing::tlws(input);
    if (*index != '{') { int *a = 0; *a = 1; }
    index++;
    SKIP_WHITE_SPACE(index);
    if (EMPTY_STRING(index)) { int *a = 0; *a = 1; }
    json::jobject result;
    while (!EMPTY_STRING(index) && *index != '}')
    {
        // Get key
        kvp entry;
        json::parsing::parse_results key = json::parsing::parse(index);
        if (key.type != json::jtype::jstring || key.value == "") { int *a = 0; *a = 1; }
        entry.first = key.value;
        index = key.remainder;

        // Get value
        SKIP_WHITE_SPACE(index);
        if (*index != ':') { int *a = 0; *a = 1; }
        index++;
        SKIP_WHITE_SPACE(index);
        json::parsing::parse_results value = json::parsing::parse(index);
        if (value.type == json::jtype::not_valid) { int *a = 0; *a = 1; }
        if (value.type == json::jtype::jstring) entry.second = "\"" + value.value + "\"";
        else entry.second = value.value;
        index = value.remainder;

        // Clean up
        SKIP_WHITE_SPACE(index);
        if (*index != ',' && *index != '}') { int *a = 0; *a = 1; }
        if (*index == ',') index++;
        result += entry;

    }
    if (EMPTY_STRING(index) || *index != '}') { int *a = 0; *a = 1; }
    index++;
    return result;
}

void json::jobject::set(const std::string &key, const std::string &value)
{
    for (size_t i = 0; i < this->size(); i++)
    {
        if (this->data.at(i).first == key)
        {
            this->data.at(i).second = value;
            return;
        }
    }
    kvp entry;
    entry.first = key;
    entry.second = value;
    this->data.push_back(entry);
}

void json::jobject::remove(const std::string &key)
{
    for (size_t i = 0; i < this->size(); i++)
    {
        if (this->data.at(i).first == key)
        {
            this->data.erase(this->data.begin() + i, this->data.begin() + i + 1);
        }
    }
}

json::jobject::operator std::string() const
{
    if (this->size() == 0) return "{}";
    std::string result = "{";
    for (size_t i = 0; i < this->size(); i++)
    {
        result += "\"" + this->data.at(i).first + "\":" + this->data.at(i).second + ",";
    }
    result.erase(result.size() - 1, 1);
    result += "}";
    return result;
}