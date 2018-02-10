package info.vividcode.oauth

interface ProtocolParameterSet : List<ProtocolParameter<*>> {

    @Suppress("UNCHECKED_CAST")
    fun <E : ProtocolParameter<*>> get(name: ProtocolParameter.Name<E>): E? = find { it.name == name } as E

    class Builder {
        private val list = mutableListOf<ProtocolParameter<*>>()

        fun add(parameter: ProtocolParameter<*>) = apply { list.add(parameter) }
        fun add(set: Collection<ProtocolParameter<*>>) = apply { list.addAll(set) }

        fun build(): ProtocolParameterSet = object : ProtocolParameterSet, List<ProtocolParameter<*>> by list {}
    }

}
