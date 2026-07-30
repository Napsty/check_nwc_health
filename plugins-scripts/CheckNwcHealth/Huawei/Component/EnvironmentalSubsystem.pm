package CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem;
our @ISA = qw(Monitoring::GLPlugin::SNMP::Item);
use strict;

sub init {
  my ($self) = @_;
  $self->get_snmp_tables_cached('ENTITY-MIB', [
  # kann man cachen, denke ich. Es wird kaum reingesteckt und rausgezogen werden
  # im laufenden Betrieb. Und falls doch und falls es monitoringseitig kracht,
  # dann beschwert euch beim Huawei (s.u. SNMP-Bremse)
  # Oder kauft kein Billigzeug
    ['modules', 'entPhysicalTable',
        'CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Module',
        sub { my ($o) = @_; $o->{entPhysicalClass} eq 'module' },
        ['entPhysicalClass', 'entPhysicalDescr', 'entPhysicalName']],
    ['fans', 'entPhysicalTable',
        'CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Fan', 
        sub { my ($o) = @_; $o->{entPhysicalClass} eq 'fan' },
        ['entPhysicalClass', 'entPhysicalDescr', 'entPhysicalName']],
    ['powersupplies', 'entPhysicalTable',
        'CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Powersupply',
        sub { my ($o) = @_; $o->{entPhysicalClass} eq 'powerSupply' },
       ['entPhysicalClass', 'entPhysicalDescr', 'entPhysicalName']],
  ], 3600);
  # heuristic tweaking. there was a device which intentionally slowed down
  # snmp responses when a large amount of data was transmitted.
  # Tatsaechlich hat Huawei sowas wie eine Denial-of-Sonstwas-Bremse drin
  # Daher reduktion auf die noetigsten Spalten und nicht uebertreiben bei
  # den PDU-Groessen.
  # update april 2026: mit dem neuen SNMP-XS-Unterbau läuft 10x in Timeout.
  # Daher nicht mehr rumfummeln an den Parametern und die "nötigsten" Spalten fliegen auch raus.
  #$self->mult_snmp_max_msg_size(10);

  # hwFanStatusTable alone already has everything we need to judge fan health
  # (presence + state), whether a fan has one blade or two. The fan-class rows
  # in entPhysicalTable are a different, redundant inventory (see investigation
  # in this session: they don't correlate by name or index with hwFanStatusTable
  # at all on some devices) that we don't need to query hwEntityStateTable for.
  # So: try hwFanStatusTable first. If it gives us present fans, entPhysicalTable's
  # fan entries are ignored entirely (not even added to @all_indices below).
  # Only fall back to entPhysicalTable's fans if hwFanStatusTable is empty or
  # has no present fans.
  $self->get_snmp_tables('HUAWEI-ENTITY-EXTENT-MIB', [
      ['fanstates', 'hwFanStatusTable', 'CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::FanStatus']
  ]);
  @{$self->{fanstates}} = grep {
    $_->{hwEntityFanPresent} eq "present";
  } @{$self->{fanstates}};
  $self->debug(sprintf "found %d present %s", scalar(@{$self->{fanstates}}), "fanstates");
  if (@{$self->{fanstates}}) {
    # done with fans via hwFanStatusTable; entPhysicalTable's fan entries
    # would otherwise be checked a second time, so drop them.
    delete $self->{fans};
  } else {
    # no (present) fans in hwFanStatusTable -- fall back to entPhysicalTable's
    # fan entries, enriched via hwEntityStateTable below like modules/powersupplies.
    delete $self->{fanstates};
  }

  my @all_indices;
  foreach my $type (qw(modules fans powersupplies)) {
    # exists-check first: @{$self->{$type}} alone would autovivify a
    # just-deleted key (e.g. fans, above) back into an empty arrayref.
    next if ! exists $self->{$type};
    foreach my $entry (@{$self->{$type}}) {
      push @all_indices, [$entry->{flat_indices}];
    }
  }
  if (@all_indices) {
    $self->debug(sprintf "searching entitystates for %d indices", scalar(@all_indices));
    my @entitystates_cache = $self->get_snmp_table_objects(
        'HUAWEI-ENTITY-EXTENT-MIB', 'hwEntityStateTable', \@all_indices, [
        "hwEntityOperStatus", "hwEntityAdminStatus", "hwEntityAlarmLight",
        "hwEntityTemperature", "hwEntityTemperatureLowThreshold",
        "hwEntityTemperatureMinorThreshold", "hwEntityTemperatureThreshold",
        "hwEntityFaultLight", "hwEntityDeviceStatus",
    ]);
    my $cached = [map { { %{$_} } } @entitystates_cache];
    $self->debug(sprintf "found %d entitystates", scalar(@{$cached}));
    foreach (qw(modules fans powersupplies)) {
      next if ! exists $self->{$_};
      $self->{entitystates} = [map { { %{$_} } } @{$cached}];
      $self->debug(sprintf "found %d %s", scalar(@{$self->{$_}}), $_);
      $self->merge_tables($_, "entitystates");
    }
  }
}


package CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::FanStatus;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish {
  my ($self) = @_;
  $self->{name} = $self->{hwEntityFanDesc} || sprintf("FAN %d/%d",
      $self->{hwEntityFanSlot}, $self->{hwEntityFanSn});
}

sub check {
  # this kind of fan comes from hwFanStatusTable
  my ($self) = @_;
  $self->add_info(sprintf 'fan %s state is %s',
      $self->{name},
      $self->{hwEntityFanState});
  if ($self->{hwEntityFanState} ne 'normal') {
    $self->add_warning();
  }
  $self->add_perfdata(
      label => 'rpm_'.$self->{name},
      value => $self->{hwEntityFanSpeed},
      uom => '%',
  );
}

package CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Entity;
our @ISA = qw(Monitoring::GLPlugin::SNMP::TableItem);
use strict;

sub finish_after_merge {
  my ($self) = @_;
  $self->{hwEntityAlarmLight} = "notSupported" if ! defined $self->{hwEntityAlarmLight};
  $self->{hwEntityTemperature} = undef
      if ($self->{hwEntityTemperature} and
      $self->{hwEntityTemperature} == 2147483647);
  # kommt auch vor, dass die nicht existieren. Im Zweifelsfall "up"
  $self->{hwEntityAdminStatus} ||= "up";
  $self->{hwEntityOperStatus} ||= "up";
}

sub check {
  my ($self) = @_;
  if ($self->{hwEntityOperStatus} eq 'down' ||
      $self->{hwEntityOperStatus} eq 'disabled' ||
      $self->{hwEntityOperStatus} eq 'offline') {
    # disabled is the important one
    # A value of disabled means the resource is totally
    #      inoperable. A value of enabled means the resource
    #      is partially or fully operableA"
    $self->add_warning();
  }
  if ($self->{hwEntityTemperature}) {
    # Es gibt viele module POWER Card 0/PWR1 temperature is 0.00
    # Selbst am Nordpol duerfte so ein Ding waermer als 0 Grad sein, also
    # gehe ich davon aus, daß da kein Sensor verbaut ist.
    $self->add_info(sprintf 'module %s temperature is %.2f',
        $self->{entPhysicalName}, $self->{hwEntityTemperature});
    $self->set_thresholds(
        metric => 'temp_'.$self->{entPhysicalName},
        warning => $self->{hwEntityTemperatureLowThreshold}.':'.$self->{hwEntityTemperatureThreshold},
        critical => $self->{hwEntityTemperatureLowThreshold}.':'.$self->{hwEntityTemperatureThreshold},
    );
    my $level = $self->check_thresholds(
        metric => 'temp_'.$self->{entPhysicalName},
        value => $self->{hwEntityTemperature});
    $self->add_message($level);
    $self->add_perfdata(
        label => 'temp_'.$self->{entPhysicalName},
        value => $self->{hwEntityTemperature},
    );
  }
  if ($self->{hwEntityAlarmLight}) {
    my @alarms = grep {
      # Hab nachschauen lassen bei einem fetten Router, der bei allen Modulen
      # und Powersupplies "alarm light status is indeterminate" angezeigt hat.
      # "die Kiste sieht in Ordnung aus"
      # Also fliegt das raus, denn beim ersten Alarm wuerde es sowieso wieder
      # heissen "mimimi, kann man das nicht clientseitig abfangen?"
      $_ ne "indeterminate";
    } grep {
      # Den auch nochmal putzen
      $_ ne "notSupported";
    } split(",", $self->{hwEntityAlarmLight});
    $self->annotate_info("alarm light status is ".join("+", @alarms))
        if (@alarms);
    foreach my $alarm (@alarms) {
      if ($alarm eq "underRepair" or $alarm eq "minor" or $alarm eq "warning") {
        $self->add_warning($alarm." alarm at ".$self->{entPhysicalName});
      } elsif ($alarm eq "critical" or $alarm eq "major") {
        $self->add_critical($alarm." alarm at ".$self->{entPhysicalName});
      } elsif ($alarm eq "alarmOutstanding") {
        # When the value of alarm outstanding is set, one or more
        # alarms is active against the resource. The fault may or may
        # not be disabling.
        # Kapier ich nicht ganz. Also erstmal Alarm, bis sich einer beschwert.
        $self->add_critical($alarm." alarm at ".$self->{entPhysicalName});
      }
    }
  }
  if ($self->{hwEntityFaultLight} and not $self->{hwEntityFaultLight} eq "notSupported") {
    # The repair status for this entity
    $self->annotate_info(sprintf 'fault light is %s',
        $self->{hwEntityFaultLight});
  }
  if ($self->{hwEntityDeviceStatus}) {
    # seems to be a new oid, i found no sample device which has it.
    $self->add_critical("status is abnormal")
        if $self->{hwEntityDeviceStatus} eq "abnormal";
  }
}


package CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Fan;
our @ISA = qw(CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Entity);
use strict;

sub check {
  # This kind of fan comes from entPhysicalTable+hwEntityStateTable, which is
  # only used as a fallback when hwFanStatusTable was empty (see init).
  # hwEntityFanPresent/-State/-Speed live in hwFanStatusTable and are therefore
  # NOT available here -- asking for them produced uninitialized-warnings.
  # A row in entPhysicalTable means the fan is plugged in, and the only health
  # signal hwEntityStateTable offers for a fan is hwEntityOperStatus (plus the
  # alarm/fault lights, which real fans usually report as notSupported).
  # There is no speed column at all, so no rpm perfdata on this path.
  #
  # TODO/offen -- die Sache mit dem absent(19):
  # HwOperState kennt neben disabled(2)/enabled(3)/offline(4) auch ein
  # absent(19), das die Vaterklasse Entity::check() (noch) nicht bemaengelt.
  # Und jetzt kommts: present(18) und absent(19) sind nirgends dokumentiert.
  # Die TEXTUAL-CONVENTION HwOperState erklaert brav und ausfuehrlich jeden
  # anderen Wert, sogar das up/down/connect, das eh nur ein NE5000E im
  # Ruecken-an-Ruecken-Betrieb je hergibt -- und ueber die zwei am Schluss
  # schweigt sie wie ein Grantler beim Fruehschoppen. In der MIB-Quelle genauso
  # wie in der S7700 MIB Reference (Issue 02, 2025-09-22). Da hat sich einer bei
  # Huawei ans Enum-Ende zwei Werte hingeschlampt und sich das Hirnschmalz fuer
  # die Beschreibung gspart. Sauber. hwEntityOperStatus ist obendrein der
  # einzige Nutzer vom TC, es gibt also kein Geschwisterobjekt, das einem aus
  # dem Schmarrn heraushelfen wuerde.
  # Zwei Lesarten, und die unterscheiden sich fei in der Konsequenz:
  #   a) "da war nie was drin" -- die Kiste kam ab Werk mit leerem Schacht.
  #      Dann waer eine Warnung nix wie Krach um garnix.
  #   b) "war drin und ist jetzt weg" -- dann gehoert gewarnt.
  # Fuer b) spricht, dass Huawei im HUAWEI-DC-TRAP-MIB ein Paerchen
  # hwFanAbsent (hwDCTraps 53) / hwFanAbsentResume (54) fuehrt. Ein Absent mit
  # zugehoerigem Resume ist ein kommendes und gehendes Ereignis und kein
  # Inventar-Merkmal -- ein ab Werk leerer Schacht feuert sowas nie.
  # Fuer a) bzw. dagegen, dass absent hier ueberhaupt Luefter meint, spricht die
  # Position im Enum: 16=linkUp, 17=linkDown, 18=present, 19=absent, das schaut
  # doch nach dem Steckstatus von einem Transceiver an einem Port-Entity aus.
  # Und wo Huawei wirklich Luefter-Anwesenheit meint, gibts ein eigenes,
  # ordentlich dokumentiertes Objekt (hwEntityFanPresent, "the fan in-position
  # status"). Waer ja auch zu einfach gwesen, das gleich hier reinzuschreiben.
  # In saemtlichen Walks der Sammlung kam absent(19) noch kein einzigs Mal vor
  # (nur enabled, linkDown, protocolUp, disabled), drum wird hier nix auf
  # Verdacht implementiert -- ich bin ja koa Gscheidhaferl. Wer irgendwann einen
  # Haufen Huawei-Geraete durchscannt und einen Luefter mit absent findet: beim
  # Besitzer nachfragen, ob da tatsaechlich ein Teil hin bzw. gezogen ist.
  # Bestaetigt sich das, gehoert hier ein add_warning() hin -- und zwar nur da
  # herin im Fan und ja nicht in Entity::check(), denn leere Schaechte sind bei
  # Modulen und Netzteilen voellig normal, und dann steht gleich wieder die
  # ganze Bagage da und mimimit.
  my ($self) = @_;
  $self->finish_after_merge();
  $self->add_info(sprintf 'fan %s admin status is %s, oper status is %s',
      $self->{entPhysicalName},
      $self->{hwEntityAdminStatus}, $self->{hwEntityOperStatus});
  $self->SUPER::check();
}


package CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Powersupply;
our @ISA = qw(CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Entity);
use strict;

sub check {
  my ($self) = @_;
  $self->finish_after_merge();
  $self->add_info(sprintf 'powersupply %s admin status is %s, oper status is %s',
      $self->{entPhysicalName},
      $self->{hwEntityAdminStatus}, $self->{hwEntityOperStatus});
  $self->SUPER::check();
}

package CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Module;
our @ISA = qw(CheckNwcHealth::Huawei::Component::EnvironmentalSubsystem::Entity);
use strict;

sub check {
  my ($self) = @_;
  $self->finish_after_merge();
  $self->add_info(sprintf 'module %s admin status is %s, oper status is %s',
      $self->{entPhysicalName},
      $self->{hwEntityAdminStatus}, $self->{hwEntityOperStatus});
  $self->SUPER::check();
}


__END__
entPhysicalAlias:
entPhysicalAssetID:
entPhysicalClass: module
entPhysicalContainedIn: 16842752
entPhysicalDescr: Assembling Components-CE5800-CE5850-48T4S2Q-EI-CE5850-48T4S2Q-
EI Switch(48-Port GE RJ45,4-Port 10GE SFP+,2-Port 40GE QSFP+,Without Fan and Pow
er Module)
entPhysicalFirmwareRev: 266
entPhysicalHardwareRev: DE51SRU1B VER D
entPhysicalIsFRU: 1
entPhysicalMfgName: Huawei
entPhysicalModelName:
entPhysicalName: CE5850-48T4S2Q-EI 1
entPhysicalParentRelPos: 1
entPhysicalSerialNum: 210235527210E2000218
entPhysicalSoftwareRev: Version 8.80 V100R003C00SPC600
entPhysicalVendorType: .1.3.6.1.4.1.2011.20021210.12.688138
hwEntityAdminStatus: unlocked
hwEntityEnvironmentalUsage: 14
hwEntityEnvironmentalUsageThreshold: 95
hwEntityFaultLight: normal
hwEntityMemSizeMega: 1837
hwEntityMemUsage: 43
hwEntityMemUsageThreshold: 95
hwEntityOperStatus: enabled
hwEntityPortType: notSupported
hwEntitySplitAttribute:
hwEntityStandbyStatus: providingService
hwEntityTemperature: 33
hwEntityTemperatureLowThreshold: 0
hwEntityTemperatureThreshold: 62
hwEntityUpTime: 34295804

# sowas gibts auch, da ist die Stromversorgung per module, nicht powerSupply
# verbaut.
[MODULE_67190797]
entPhysicalClass: module
entPhysicalDescr: POWER Card
entPhysicalName: POWER Card 0/PWR1
hwEntityAdminStatus: unlocked
hwEntityAlarmLight: unknown_
hwEntityBoardName: POWER
hwEntityCpuMaxUsage: 0
hwEntityCpuUsage: 0
hwEntityCpuUsageLowThreshold: 0
hwEntityCpuUsageThreshold: 0
hwEntityFaultLight: notSupported
hwEntityFaultLightKeepTime: 0
hwEntityMemSize: 0
hwEntityMemUsage: 0
hwEntityMemUsageThreshold: 0
hwEntityOperStatus: enabled
hwEntitySplitAttribute: 
hwEntityStandbyStatus: notSupported
hwEntityTemperature: 0
hwEntityTemperatureLowThreshold: 0
hwEntityTemperatureThreshold: 0
hwEntityUpTime: 0
hwEntityVoltage: 0
hwEntityVoltageHighThreshold: 0
hwEntityVoltageLowThreshold: 0



