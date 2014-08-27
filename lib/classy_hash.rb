# Classy Hash: Keep Your Hashes Classy
# Created May 2014 by Mike Bourgeous, DeseretBook.com
# Copyright (C)2014 Deseret Book and Contributors (see git history)
# See LICENSE and README.md for details.

require 'continuation'

# This module contains the ClassyHash methods for making sure Ruby Hash objects
# match a given schema.  ClassyHash runs fast by taking advantage of Ruby
# language features and avoiding object creation during validation.
module ClassyHash
  # Raised when a validation fails.  Allows ClassyHash#validate_full to
  # continue validation and gather all errors.
  class SchemaViolationError < StandardError
    # The list of errors passed to the constructor.  Contains an Array of Hashes:
    #   [
    #     { full_path: ClassyHash.join_path(parent_path, key), message: message },
    #     ...
    #   ]
    attr_reader :entries

    # Initializes a schema violation error with the given list of schema
    # +errors+ and a continuation (+cont+) for resuming execution.
    def initialize(errors = [], cont = nil)
      @entries, @cont = errors, cont
    end

    # Resumes execution using the continuation passed to the constructor.
    def continue
      @cont.call
    end

    # Joins all errors passed to the constructor into a comma-separated String.
    def full_message
      @entries.each_with_object [] do |entry, list|
        if entry[:full_path]
          list << "#{entry[:full_path]} is not #{entry[:message]}"
        else
          list << entry[:message]
        end
      end.join(', ')
    end
    alias_method :to_s, :full_message
  end


  # Validates a +hash+ against a +schema+.  The +parent_path+ parameter is used
  # internally to generate error messages.
  def self.validate(hash, schema, parent_path=nil)
    raise 'Must validate a Hash' unless hash.is_a?(Hash) # TODO: Allow validating other types by passing to #check_one?
    raise 'Schema must be a Hash' unless schema.is_a?(Hash) # TODO: Allow individual element validations?

    schema.each do |key, constraint|
      if hash.include?(key)
        self.check_one(key, hash[key], constraint, parent_path)
      elsif !(constraint.is_a?(Array) && constraint.include?(:optional))
        self.raise_error(parent_path, key, "present")
      end
    end

    nil
  end

  # As with #validate, but members not specified in the +schema+ are forbidden.
  # Only the top-level schema is strictly validated.
  def self.validate_strict(hash, schema, parent_path=nil)
    raise 'Must validate a Hash' unless hash.is_a?(Hash) # TODO: Allow validating other types by passing to #check_one?
    raise 'Schema must be a Hash' unless schema.is_a?(Hash) # TODO: Allow individual element validations?

    unless (hash.keys - schema.keys).empty?
      raise_error(nil, nil, 'Hash contains members not specified in schema')
    end

    # TODO: Strict validation for nested schemas as well

    self.validate(hash, schema, parent_path)
  end

  # Similar to #validate (or #validate_strict if +strict+ is true), but
  # collects *all* schema violation errors.
  def self.validate_full(hash, schema, strict = false, &block)
    error_entries = []

    begin
      strict ? validate_strict(hash, schema) : validate(hash, schema)
    rescue SchemaViolationError => error
      error_entries.concat error.entries
      error.continue
    end

    if block_given?
      error_entries.each(&block)
    elsif !error_entries.empty?
      raise SchemaViolationError.new(error_entries)
    end

    nil
  end

  # Raises an error unless the given +value+ matches one of the given multiple
  # choice +constraints+.
  def self.check_multi(key, value, constraints, parent_path=nil)
    if constraints.length == 0
        self.raise_error(parent_path, key, "a valid multiple choice constraint (array must not be empty)")
    end

    # Optimize the common case of a direct class match
    return if constraints.include?(value.class)

    error = nil
    constraints.each do |c|
      next if c == :optional
      begin
        self.check_one(key, value, c, parent_path)
        return
      rescue => e
        # Throw schema and array errors immediately
        if (c.is_a?(Hash) && value.is_a?(Hash)) ||
          (c.is_a?(Array) && value.is_a?(Array) && c.length == 1 && c.first.is_a?(Array))
          raise e
        end
      end
    end

    self.raise_error(parent_path, key, "one of #{multiconstraint_string(constraints)}")
  end

  # Generates a semi-compact String describing the given +constraints+.
  def self.multiconstraint_string(constraints)
    constraints.map{|c|
      if c.is_a?(Hash)
        "{...schema...}"
      elsif c.is_a?(Array)
        "[#{self.multiconstraint_string(c)}]"
      elsif c == :optional
        nil
      else
        c.inspect
      end
    }.compact.join(', ')
  end

  # Checks a single value against a single constraint.
  def self.check_one(key, value, constraint, parent_path=nil)
    case constraint
    when Class
      # Constrain value to be a specific class
      if constraint == TrueClass || constraint == FalseClass
        unless value == true || value == false
          self.raise_error(parent_path, key, "true or false")
        end
      elsif !value.is_a?(constraint)
        self.raise_error(parent_path, key, "a/an #{constraint}")
      end

    when Hash
      # Recursively check nested Hashes
      self.raise_error(parent_path, key, "a Hash") unless value.is_a?(Hash)
      self.validate(value, constraint, self.join_path(parent_path, key))

    when Array
      # Multiple choice or array validation
      if constraint.length == 1 && constraint.first.is_a?(Array)
        # Array validation
        self.raise_error(parent_path, key, "an Array") unless value.is_a?(Array)

        constraints = constraint.first
        value.each_with_index do |v, idx|
          self.check_multi(idx, v, constraints, self.join_path(parent_path, key))
        end
      else
        # Multiple choice
        self.check_multi(key, value, constraint, parent_path)
      end

    when Proc
      # User-specified validator
      result = constraint.call(value)
      if result != true
        self.raise_error(parent_path, key, result.is_a?(String) ? result : "accepted by Proc")
      end

    when Range
      # Range (with type checking for common classes)
      if constraint.min.is_a?(Integer) && constraint.max.is_a?(Integer)
        self.raise_error(parent_path, key, "an Integer") unless value.is_a?(Integer)
      elsif constraint.min.is_a?(Numeric)
        self.raise_error(parent_path, key, "a Numeric") unless value.is_a?(Numeric)
      elsif constraint.min.is_a?(String)
        self.raise_error(parent_path, key, "a String") unless value.is_a?(String)
      end

      unless constraint.cover?(value)
        self.raise_error(parent_path, key, "in range #{constraint.inspect}")
      end

    when :optional
      # Optional key marker in multiple choice validators
      nil

    else
      # Unknown schema constraint
      self.raise_error(parent_path, key, "a valid schema constraint: #{constraint.inspect}")
    end

    nil
  end

  def self.join_path(parent_path, key)
    parent_path ? "#{parent_path}[#{key.inspect}]" : key.inspect
  end

  # Raises an error indicating that the given +key+ under the given
  # +parent_path+ fails because the value "is not #{+message+}"
  #
  # If parent_path and key are both nil, then the error message will just be
  # the given +message+.
  def self.raise_error(parent_path, key, message)
    callcc do |cont|
      entry = {
        full_path: (parent_path || key) && ClassyHash.join_path(parent_path, key),
        message: message
      }
      raise SchemaViolationError.new([entry], cont)
    end
  end
end

require 'classy_hash/generate'

if !Kernel.const_defined?(:CH)
  CH = ClassyHash
end
