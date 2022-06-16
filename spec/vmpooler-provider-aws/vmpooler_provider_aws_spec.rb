require 'rspec'

describe 'VmpoolerProviderAws' do
  context 'when creating class ' do
    it 'sets a version' do
      expect(VmpoolerProviderAws::VERSION).not_to be_nil
    end
  end
end