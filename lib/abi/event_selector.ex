defmodule ABI.EventSelector do
  @type type ::
          {:uint, integer()}
          | :bool
          | :bytes
          | :string
          | :address
          | {:array, type}
          | {:array, type, non_neg_integer}
          | {:tuple, [type]}

  @type arg ::
          {:bool, type, String.t()}

  @type t :: %__MODULE__{
          event: String.t(),
          args: [arg]
        }

  defstruct [:event, :args]

  # def try do
  #   parse_json()
  #   |> parse_specification_item()
  # end

  def parse_specification_item(%{"type" => "event"} = item) do
    %{
      "name" => event_name,
      "inputs" => named_args
    } = item

    arg_types = Enum.map(named_args, &parse_specification_type/1)

    %ABI.EventSelector{
      event: event_name,
      args: arg_types
    }
  end

  def parse_specification_item(_), do: nil

  def encode(%__MODULE__{} = event_selector) do
    args = get_args(event_selector) |> Enum.join(",")

    "#{event_selector.event}(#{args})"
  end

  defp get_args(event_selector) do
    for {_, arg, _} <- event_selector.args do
      get_arg(arg)
    end
  end

  defp get_arg(nil), do: nil
  defp get_arg({:int, size}), do: "int#{size}"
  defp get_arg({:uint, size}), do: "uint#{size}"
  defp get_arg(:address), do: "address"
  defp get_arg(:bool), do: "bool"
  defp get_arg({:fixed, element_count, precision}), do: "fixed#{element_count}x#{precision}"
  defp get_arg({:ufixed, element_count, precision}), do: "ufixed#{element_count}x#{precision}"
  defp get_arg({:bytes, size}), do: "bytes#{size}"
  defp get_arg(:function), do: "function"

  defp get_arg({:array, type, element_count}), do: "#{get_arg(type)}[#{element_count}]"

  defp get_arg(:bytes), do: "bytes"
  defp get_arg(:string), do: "string"
  defp get_arg({:array, type}), do: "#{get_arg(type)}[]"

  defp get_arg({:tuple, types}) do
    encoded_types = Enum.map(types, &get_arg/1)
    "(#{Enum.join(encoded_types, ",")})"
  end

  defp get_arg(els), do: raise("Unsupported type: #{inspect(els)}")

  defp parse_specification_type(%{"indexed" => indexed, "name" => name, "type" => type}) do
    {indexed, ABI.Parser.parse!(type, as: :type), name}
  end

  # defp parse_json do
  #   {:ok, content} = File.read(File.cwd!() <> "/priv/transfer.abi.json")
  #   Jason.decode!(content)
  # end

  defp hash(signature) do
    ExthCrypto.Hash.Keccak.kec(signature) |> Base.encode16(case: :lower)
  end

  def decode(%__MODULE__{} = event_selector, event_logs) do
    Enum.filter(event_logs, fn event_log ->
      %{"topics" => [event_sign_hash | _]} = event_log
      "0x#{encode(event_selector) |> hash()}" == event_sign_hash
    end)
    |> Enum.map(fn event_log ->
      topics = Map.get(event_log, "topics", [])
      data = Map.get(event_log, "data", "")

      indexed_map =
        event_selector.args
        |> Enum.filter(fn {indexed, _, _} -> indexed == true end)
        |> Enum.with_index(1)
        |> Enum.map(fn {{_, type, name}, index} ->
          value =
            Enum.at(topics, index)
            |> String.slice(2..-1)
            |> Base.decode16!(case: :lower)
            |> ABI.TypeDecoder.decode_raw([type])
            |> List.first()

          {name, value}
        end)
        |> Map.new()

      other_map =
        event_selector.args
        |> Enum.filter(fn {indexed, _, _} -> indexed == false end)
        |> Enum.with_index()
        |> Enum.map(fn {{_, type, name}, index} ->
          value =
            String.slice(data, (2 + 64 * index)..(65 + 64 * index))
            |> Base.decode16!(case: :lower)
            |> ABI.TypeDecoder.decode_raw([type])
            |> List.first()

          {name, value}
        end)
        |> Map.new()

      Map.merge(indexed_map, other_map)
    end)
  end
end
