# frozen_string_literal: true

require "json"
require "capybara/rspec"
require "capybara/poltergeist"
require "fileutils"
# BROK
FileUtils.mkdir_p(File.join(File.dirname(__FILE__), "../", "screenshots"))

# Automatically require all files in spec/support directory
Dir[File.join(File.dirname(File.dirname(__FILE__)), "spec", "support", "**", "*.rb")]
  .each { |f| require f }

def environment_path
  ENV.fetch("ENVIRONMENT", "#{File.join(File.dirname(__FILE__), "../../")}caasp-kvm/environment.json")
end

def environment(action: :read, body: nil)
  env = JSON.parse(File.read(environment_path))
  abort("Please specify kubernetesExternalHost in environment.json") unless env["kubernetesExternalHost"]
  abort("Please specify at least 2 minions in environment.json") if env["minions"].count < 2

  case action
  when :read
    env
  when :update
    if body
      File.open(environment_path, "w") do |f|
        f.puts(JSON.pretty_generate(body))
      end
    end
  end
  env
rescue JSON::ParserError
  raise("Invalid JSON format")
rescue StandardError
  raise("Please specify ENVIRONMENT to point to a valid environment.json path")
end

# returns a new env with a minion set as $status
def set_minion_status(minion_id, status)
  env = JSON.parse(File.read(environment_path))
  updated_minions = env["minions"].each do |m|
    m["minionID"] == minion_id && m["status"] = status
  end
  env["minions"] = updated_minions
  env
end

# returns a new env with a feature set as $value
def set_feature(feature, value)
  env = JSON.parse(File.read(environment_path))
  env.fetch("features", {})[feature] = value
  env
end

def admin_minion
  environment["minions"].detect { |m| m["role"] == "admin" }
end

def node_number
  environment["minions"].count { |element| element["role"] != "admin" && element["status"] != "removed" }
end

def master_node_number
  environment["minions"].count { |element| element["role"] == "master" && element["status"] != "removed" }
end

def worker_node_number
  environment["minions"].count { |element| element["role"] == "worker" && element["status"] != "removed" }
end

def node_removable?(role: "master")
  cnt = environment["minions"].count { |element| element["role"] == role && element["status"] != "removed" }
  !cnt.zero? && cnt != 1
end

Capybara.register_driver :poltergeist do |app|
  options = {
    timeout:           180,
    js_errors:         true,
    phantomjs_options: [
      "--proxy-type=none",
      "--load-images=yes"
    ]
  }
  # NOTE: uncomment the line below to get more info on the current run.
  # options[:debug] = true
  Capybara::Poltergeist::Driver.new(app, options)
end

Capybara.default_driver = :poltergeist

Capybara.configure do |config|
  config.javascript_driver = :poltergeist
  config.default_max_wait_time = 5
  config.match = :one
  config.exact_options = true
  config.ignore_hidden_elements = true
  config.visible_text_only = true
  config.default_selector = :css
  config.app_host = "https://#{environment["dashboardExternalHost"]}"
end

RSpec.configure do |config|
  # rspec-expectations config goes here. You can use an alternate
  # assertion/expectation library such as wrong or the stdlib/minitest
  # assertions if you prefer.
  config.expect_with :rspec do |expectations|
    # This option will default to `true` in RSpec 4. It makes the `description`
    # and `failure_message` of custom matchers include text for helper methods
    # defined using `chain`, e.g.:
    #     be_bigger_than(2).and_smaller_than(4).description
    #     # => "be bigger than 2 and smaller than 4"
    # ...rather than:
    #     # => "be bigger than 2"
    expectations.include_chain_clauses_in_custom_matcher_descriptions = true
  end

  # rspec-mocks config goes here. You can use an alternate test double
  # library (such as bogus or mocha) by changing the `mock_with` option here.
  config.mock_with :rspec do |mocks|
    # Prevents you from mocking or stubbing a method that does not exist on
    # a real object. This is generally recommended, and will default to
    # `true` in RSpec 4.
    mocks.verify_partial_doubles = true
  end

  # This option will default to `:apply_to_host_groups` in RSpec 4 (and will
  # have no way to turn it off -- the option exists only for backwards
  # compatibility in RSpec 3). It causes shared context metadata to be
  # inherited by the metadata hash of host groups and examples, rather than
  # triggering implicit auto-inclusion in groups with matching metadata.
  config.shared_context_metadata_behavior = :apply_to_host_groups

  # fail fast
  config.fail_fast = true

  # Set a fallback timeout around the tests
  timeout = ENV.fetch("TEST_TIMEOUT", 7200).to_i

  config.around do |test|
    begin
      Timeout.timeout(timeout) { test.run }
    rescue Timeout::Error
      save_screenshot("screenshots/timeout-#{Time.now.to_i}.png", full: true)
      raise
    end
  end

  config.after do |example|
    if example.exception
      save_screenshot("screenshots/error_state-#{Time.now.to_i}.png", full: true)
    end
  end
end
