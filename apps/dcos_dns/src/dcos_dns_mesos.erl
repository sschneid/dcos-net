-module(dcos_dns_mesos).
-behavior(gen_server).

-include("dcos_dns.hrl").
-include_lib("dns/include/dns.hrl").

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").
-endif.

%% API
-export([
    start_link/0
]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2,
    handle_info/2, terminate/2, code_change/3]).

-type task() :: dcos_net_mesos_state:task().
-type task_id() :: dcos_net_mesos_state:task_id().

-define(DCOS_DNS_TTL, 5).
-define(IS_RUNNING(TS), not is_boolean(TS)).

-record(state, {
    ref :: reference(),
    tasks :: #{ task_id() => [dns:dns_rr()] },
    master_ref :: reference(),
    masters = [] :: [dns:dns_rr()]
}).

-spec(start_link() -> {ok, Pid :: pid()} | ignore | {error, Reason :: term()}).
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([]) ->
    self() ! init,
    {ok, []}.

handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(init, State) ->
    case dcos_net_mesos_state:subscribe() of
        {ok, Ref, MTasks} ->
            MRef = erlang:start_timer(0, self(), masters),
            Tasks = task_records(MTasks),
            ok = push_tasks(Tasks),
            {noreply, #state{ref=Ref, tasks=Tasks, master_ref=MRef}};
        {error, _Error} ->
            self() ! init,
            timer:sleep(100),
            {noreply, State}
    end;
handle_info({task_updated, Ref, TaskId, Task},
            #state{ref=Ref, tasks=Tasks}=State) ->
    ok = dcos_net_mesos_state:next(Ref),
    TaskState = maps:get(state, Task),
    case {?IS_RUNNING(TaskState), maps:is_key(TaskId, Tasks)} of
        {Same, Same} ->
            {noreply, State};
        {false, true} ->
            {Records, Tasks0} = maps:take(TaskId, Tasks),
            ok = push_ops(?DCOS_DOMAIN, [{remove_all, Records}]),
            {noreply, State#state{tasks=Tasks0}};
        {true, false} ->
            TaskRecords = task_records(TaskId, Task),
            Tasks0 = maps:put(TaskId, TaskRecords, Tasks),
            ok = push_ops(?DCOS_DOMAIN, [{add_all, TaskRecords}]),
            {noreply, State#state{tasks=Tasks0}}
    end;
handle_info({'DOWN', Ref, process, _Pid, Info}, #state{ref=Ref}=State) ->
    {stop, Info, State};
handle_info({timeout, Ref, masters},
            #state{master_ref=Ref, masters=MRecords}=State) ->
    Ref0 = erlang:start_timer(5000, self(), masters),
    ZoneName = ?DCOS_DOMAIN,
    MRecords0 = master_records(ZoneName),
    ok = push_diff(ZoneName, MRecords0, MRecords),
    {noreply, State#state{master_ref=Ref0, masters=MRecords}};
handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec(task_records(#{task_id() => task()}) -> #{task_id() => [dns:dns_rr()]}).
task_records(Tasks) ->
    maps:fold(fun (TaskId, #{state := TaskState} = Task, Acc) ->
        case ?IS_RUNNING(TaskState) of
            true ->
                TaskRecords = task_records(TaskId, Task),
                maps:put(TaskId, TaskRecords, Acc);
            false -> Acc
        end
    end, #{}, Tasks).

-spec(task_records(task_id(), task()) -> dns:dns_rr()).
task_records(_TaskId, Task) ->
    lists:flatten([
        task_agentip(Task),
        task_containerip(Task),
        task_autoip(Task)
    ]).

-spec(task_agentip(task()) -> [dns:dns_rr()]).
task_agentip(#{name := Name, framework := Fwrk, agent_ip := AgentIP}) ->
    DName = format_name([Name, Fwrk, <<"agentip">>], ?DCOS_DOMAIN),
    dns_records(DName, [AgentIP]).

-spec(task_containerip(task()) -> [dns:dns_rr()]).
task_containerip(#{name := Name, framework := Fwrk,
                    container_ip := ContainerIPs}) ->
    DName = format_name([Name, Fwrk, <<"containerip">>], ?DCOS_DOMAIN),
    dns_records(DName, ContainerIPs);
task_containerip(_Task) ->
    [].

-spec(task_autoip(task()) -> [dns:dns_rr()]).
task_autoip(#{name := Name, framework := Fwrk, agent_ip := AgentIP} = Task) ->
    %% if task.port_mappings then agent_ip else container_ip
    DName = format_name([Name, Fwrk, <<"autoip">>], ?DCOS_DOMAIN),
    ContainerIPs = maps:get(container_ip, Task, [AgentIP]),
    Ports = maps:get(ports, Task, []),
    dns_records(DName,
        case lists:any(fun is_port_mapping/1, Ports) of
            true -> [AgentIP];
            false -> ContainerIPs
        end
    ).

-spec(is_port_mapping(dcos_net_mesos_state:task_port()) -> boolean()).
is_port_mapping(#{host_port := _HPort, port := _Port}) ->
    true;
is_port_mapping(_Port) ->
    false.

%%%===================================================================
%%% DNS functions
%%%===================================================================

-spec(push_tasks(#{task_id() => task()}) -> ok).
push_tasks(Tasks) ->
    ZoneName = ?DCOS_DOMAIN,
    Records = maps:values(Tasks),
    Records0 =
        lists:flatten([
            Records,
            zone_records(ZoneName),
            leader_records(ZoneName)
        ]),
    push_zone(ZoneName, Records0).

-spec(dns_records(dns:dname(), [inet:ip_address()]) -> [dns:dns_rr()]).
dns_records(DName, IPs) ->
    [dns_record(DName, IP) || IP <- IPs].

-spec(dns_record(dns:dname(), inet:ip_address()) -> dns:dns_rr()).
dns_record(DName, IP) ->
    {Type, Data} =
        case dcos_dns:family(IP) of
            inet -> {?DNS_TYPE_A, #dns_rrdata_a{ip = IP}};
            inet6 -> {?DNS_TYPE_AAAA, #dns_rrdata_aaaa{ip = IP}}
        end,
    #dns_rr{name = DName, type = Type, ttl = ?DCOS_DNS_TTL, data = Data}.

-spec(format_name([binary()], binary()) -> binary()).
format_name(ListOfNames, Postfix) ->
    ListOfNames1 = lists:map(fun mesos_state:label/1, ListOfNames),
    ListOfNames2 = lists:map(fun list_to_binary/1, ListOfNames1),
    Prefix = join(ListOfNames2, <<".">>),
    <<Prefix/binary, ".", Postfix/binary>>.

-spec(join([binary()], binary()) -> binary()).
join(List, Sep) ->
    SepSize = size(Sep),
    <<Sep:SepSize/binary, Result/binary>> =
        << <<Sep/binary, X/binary>> || X <- List >>,
    Result.

%%%===================================================================
%%% Master functions
%%%===================================================================

-spec(master_records(dns:dname()) -> [dns:dns_rr()]).
master_records(ZoneName) ->
    Masters = [IP || {IP, _} <- dcos_dns_config:mesos_resolvers()],
    dns_records(<<"master.", ZoneName/binary>>, Masters).

-spec(leader_records(dns:dname()) -> dns:dns_rr()).
leader_records(ZoneName) ->
    IP = dcos_net_dist:nodeip(),
    dns_record(<<"leader.", ZoneName/binary>>, IP).

%%%===================================================================
%%% Lashup functions
%%%===================================================================

-spec(push_zone(dns:dname(), [dns:dns_rr()]) -> ok).
push_zone(ZoneName, Records) ->
    Key = ?LASHUP_KEY(ZoneName),
    LRecords = lashup_kv:value(Key),
    LRecords0 =
        case lists:keyfind(?RECORDS_FIELD, 1, LRecords) of
            false -> [];
            {_, LR} -> LR
        end,
    push_diff(ZoneName, Records, LRecords0).

-spec(push_diff(dns:dname(), [dns:dns_rr()], [dns:dns_rr()]) -> ok).
push_diff(ZoneName, New, Old) ->
    case complement(New, Old) of
        {[], []} ->
            ok;
        {AddRecords, RemoveRecords} ->
            Ops = [{remove_all, RemoveRecords}, {add_all, AddRecords}],
            push_ops(ZoneName, Ops)
    end.

-spec(push_ops(dns:dname(), [riak_dt_orswot:orswot_op()]) -> ok).
push_ops(ZoneName, Ops) ->
    % TODO: use lww
    Key = ?LASHUP_KEY(ZoneName),
    Updates = [{update, ?RECORDS_FIELD, Op} || Op <- Ops],
    case lashup_kv:request_op(Key, {update, Updates}) of
        {ok, _} -> ok
    end.

-spec(zone_records(dns:dname()) -> [dns:dns_rr()]).
zone_records(ZoneName) ->
    [
        #dns_rr{
            name = ZoneName,
            type = ?DNS_TYPE_SOA,
            ttl = 3600,
            data = #dns_rrdata_soa{
                mname = <<"ns.spartan">>,
                rname = <<"support.mesosphere.com">>,
                serial = 1,
                refresh = 60,
                retry = 180,
                expire = 86400,
                minimum = 1
            }
        },
        #dns_rr{
            name = ZoneName,
            type = ?DNS_TYPE_NS,
            ttl = 3600,
            data = #dns_rrdata_ns{
                dname = <<"ns.spartan">>
            }
        }
    ].

%%%===================================================================
%%% Complement functions
%%%===================================================================

%% @doc Return {A\B, B\A}
-spec(complement([A], [B]) -> {[A], [B]}
    when A :: term(), B :: term()).
complement(ListA, ListB) ->
    complement(
        lists:sort(ListA),
        lists:sort(ListB),
        [], []).

-spec(complement([A], [B], [A], [B]) -> {[A], [B]}
    when A :: term(), B :: term()).
complement([], ListB, Acc, Bcc) ->
    {Acc, ListB ++ Bcc};
complement(ListA, [], Acc, Bcc) ->
    {ListA ++ Acc, Bcc};
complement([A|ListA], [A|ListB], Acc, Bcc) ->
    complement(ListA, ListB, Acc, Bcc);
complement([A|_]=ListA, [B|ListB], Acc, Bcc) when A > B ->
    complement(ListA, ListB, Acc, [B|Bcc]);
complement([A|ListA], [B|_]=ListB, Acc, Bcc) when A < B ->
    complement(ListA, ListB, [A|Acc], Bcc).

-ifdef(TEST).

complement_test() ->
    {A, B} =
        complement(
            [a, 0, b, 1, c, 2],
            [e, 0, d, 1, f, 2]),
    ?assertEqual(
        {[a, b, c], [d, e, f]},
        {lists:sort(A), lists:sort(B)}).

-endif.
