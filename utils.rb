require 'duration'

OrigDuration = Duration
Object.send(:remove_const, :Duration)
class Duration < OrigDuration
  def initialize(kwargs = {})
    @smallest = :seconds
    @largest = :weeks
    if kwargs[:smallest_unit]
      @smallest = kwargs[:smallest_unit]
      kwargs.delete(:smallest_unit)
    end
    if kwargs[:largest_unit]
      @largest = kwargs[:largest_unit]
      kwargs.delete(:largest_unit)
    end
    @smallest = kwargs.keys.first if kwargs.size == 1
    super(**kwargs)
  end

  def to_s(short: true, smallest_unit: nil, largest_unit: nil)
    smallest_unit = @smallest if smallest_unit.nil?
    largest_unit = @largest if largest_unit.nil?

    parts = []
    shortmap = {:weeks => 'wk', :days => 'd', :hours => 'h', :minutes => 'm',
      :seconds => 's'}
    units = self.to_a

    # first accumulate everything up to the largest_unit
    acc = 0
    until units.empty? do
      unit, v = units.pop
      if unit != largest_unit
        acc += v * Duration::MULTIPLES[unit]
        next
      end
      v += acc / Duration::MULTIPLES[unit]
      units.push [unit, v]
      break
    end
    units = units.reject { |unit, v| v == 0 }
    units << [smallest_unit, 0] if units.empty?

    # then continue until we get to the smallest_unit
    until units.empty?
      unit, v = units.pop
      is_smallest = (unit == smallest_unit)
      unit = shortmap[unit] if short
      unit = " #{unit}" unless short
      parts << "#{v}#{unit}"
      break if is_smallest
    end

    parts.join(short ? ' ' : ', ')
  end
end

class Hash
  def symbolize
    self.transform_keys(&:to_sym)
  end
  def symbolize!
    self.transform_keys!(&:to_sym)
  end
end
