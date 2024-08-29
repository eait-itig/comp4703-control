class Hash
  def symbolize
    self.transform_keys(&:to_sym)
  end
  def symbolize!
    self.transform_keys!(&:to_sym)
  end
end
