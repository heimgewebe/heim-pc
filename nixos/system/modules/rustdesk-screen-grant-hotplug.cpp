#include <QGuiApplication>
#include <QScreen>
#include <QTimer>
#include <QSet>
#include <QProcess>
#include <algorithm>
#include <QDBusArgument>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusVariant>
#include <QDataStream>
#include <QDir>
#include <QFile>
#include <QRegularExpression>
#include <QStringList>
#include <QVariant>
#include <iostream>

int converge(QGuiApplication &app, bool apply) {
    // KDE's persisted ScreenCast output identities are logical screen positions,
    // not connector names. Derive them from the same Qt Wayland QScreens as KDE.
    QSet<QString> names;
    QStringList desired;
    for (const QScreen *screen: app.screens()) {
        const QString name=screen->name();
        if (name!="DP-1" && name!="DP-2" && name!="Virtual-iPadRemote") {
            std::cerr << "UNKNOWN_OUTPUT_NAME\n";
            return 14;
        }
        if (names.contains(name)) return 15;
        names.insert(name);
        const QPoint pos=screen->geometry().topLeft();
        desired.append(QString("%1x%2").arg(pos.x()).arg(pos.y()));
    }
    // DP-2 is the stable fallback. The virtual output is optional: starting
    // krfb-virtualmonitor again when KWin retains its output can duplicate
    // Virtual-iPadRemote and produce black/transparent ScreenCast frames.
    // Preserve unattended DP-2-only operation rather than blocking grant repair.
    if (!names.contains("DP-2") || desired.isEmpty() || desired.size()>3) return 16;
    std::sort(desired.begin(), desired.end());
    QSet<QString> unique;
    for (const auto &id: desired) unique.insert(id);
    static int overlapRepairs = 0;
    if (desired.size() != unique.size()) {
        // When DP-1 is re-enabled, KScreen can leave DP-1 and DP-2 both at 0,0.
        // Derive left-to-right positions from connector names and CURRENT
        // logical width, never hardcode indexes or framebuffer dimensions.
        const QScreen *dp1=nullptr,*dp2=nullptr,*virtualScreen=nullptr;
        for (const auto *screen: app.screens()) {
            if (screen->name()=="DP-1") dp1=screen;
            else if (screen->name()=="DP-2") dp2=screen;
            else if (screen->name()=="Virtual-iPadRemote") virtualScreen=screen;
        }
        if (!apply || !dp1 || !dp2 || !virtualScreen || overlapRepairs>=3) {
            std::cerr << "DUPLICATE_SCREEN_COORDINATES\n"; return 17;
        }
        overlapRepairs++;
        const int dp2x=dp1->geometry().width();
        const int virtx=dp2x+dp2->geometry().width();
        const QStringList args{
            QStringLiteral("output.DP-1.position.0,0"),
            QString("output.DP-2.position.%1,0").arg(dp2x),
            QString("output.Virtual-iPadRemote.position.%1,0").arg(virtx)
        };
        const int code=QProcess::execute(QStringLiteral("kscreen-doctor"),args);
        if (code!=0) {
            std::cerr<<"LAYOUT_RECOVERY_FAILED "<<code<<"\n";return 18;
        }
        std::cout<<"LAYOUT_RECOVERED_BY_CONNECTOR "<<dp2x<<","<<virtx<<std::endl;
        QTimer::singleShot(1500,&app,[&app](){converge(app,true);});
        return 0;
    }
    overlapRepairs=0;
    const QString base = QDir::homePath();
    QFile config(base + "/.config/rustdesk/RustDesk_local.toml");
    if (!config.open(QIODevice::ReadOnly)) return 2;
    const auto match = QRegularExpression("(?m)^wayland-restore-token\\s*=\\s*'([^']+)'")
                           .match(QString::fromUtf8(config.readAll()));
    if (!match.hasMatch()) return 3;
    const QString token = match.captured(1);
    const auto bus = QDBusConnection::sessionBus();
    QDBusMessage lookup = QDBusMessage::createMethodCall(
        "org.freedesktop.impl.portal.PermissionStore",
        "/org/freedesktop/impl/portal/PermissionStore",
        "org.freedesktop.impl.portal.PermissionStore", "Lookup");
    lookup << QStringLiteral("screencast") << token;
    auto read = [&]() -> QByteArray {
        auto reply = bus.call(lookup, QDBus::Block, 9000);
        if (reply.type() == QDBusMessage::ErrorMessage || reply.arguments().size() != 2) return {};
        auto nested = reply.arguments().at(1).value<QDBusVariant>().variant();
        if (!nested.canConvert<QDBusArgument>()) return {};
        const auto dbus = nested.value<QDBusArgument>();
        QString provider; quint32 version = 0; QDBusVariant payload;
        dbus.beginStructure(); dbus >> provider >> version >> payload; dbus.endStructure();
        if (provider != "KDE" || version != 1) return {};
        return payload.variant().toByteArray();
    };
    const QByteArray old = read();
    if (old.isEmpty()) {
        std::cerr << "NO_CURRENT_VALID_KDE_GRANT\n";
        return 4;
    }
    QDataStream in(old);
    quint32 fields = 0, type = 0, count = 0;
    quint8 nullbit = 2;
    QString key;
    in >> fields >> key >> type >> nullbit;
    const qint64 countOffset = in.device()->pos();
    in >> count;
    QStringList previous;
    for (quint32 i = 0; i < count && i < 6; ++i) {
        QVariant value;
        in >> value;
        previous.append(value.toString());
    }
    const qint64 afterList = in.device()->pos();
    QString nextKey;
    in >> nextKey;
    if (in.status() != QDataStream::Ok || fields != 3 || key != "outputs" ||
        type != 9 || nullbit != 0 || count < 1 || count > 4 ||
        previous.size() != static_cast<int>(count) || nextKey != "region") {
        std::cerr << "UNEXPECTED_STORED_GRANT_FORMAT\n";
        return 5;
    }
    const QRegularExpression coordinate("^-?[0-9]+x-?[0-9]+$");
    for (const auto &savedId: previous) {
        if (!coordinate.match(savedId).hasMatch()) {
            std::cerr << "UNKNOWN_PAST_SCREEN_ID\n"; return 6;
        }
    }
    std::cout << "BEFORE " << previous.join(",").toStdString()
              << " DESIRED " << desired.join(",").toStdString() << '\n';
    if (previous == desired) {
        std::cout << "GRANT_ALREADY_MATCHES_CURRENT_OUTPUTS\n";
        return 0;
    }
    QByteArray updated;
    QDataStream out(&updated, QIODevice::WriteOnly);
    out.writeRawData(old.constData(), countOffset);
    out << quint32(desired.size());
    for (const auto &name : desired) out << QVariant(name);
    out.writeRawData(old.constData()+afterList, old.size()-afterList);

    QDataStream check(updated);
    quint32 nfields=0, ntype=0, ncount=0; quint8 nnull=2;
    QString nkey; check >> nfields >> nkey >> ntype >> nnull >> ncount;
    QStringList result;
    for (quint32 i=0; i<ncount && i<6; ++i) { QVariant v; check >> v; result << v.toString(); }
    QString ntail; check >> ntail;
    if (check.status()!=QDataStream::Ok || nfields!=3 || nkey!="outputs" ||
        ntype!=9 || nnull!=0 || ncount!=quint32(desired.size()) || result!=desired || ntail!="region") {
        std::cerr << "REENCODE_READBACK_INVALID\n"; return 7;
    }
    if (!apply) {
        std::cout << "DRY_RUN_OK source_bytes=" << old.size()
                  << " new_bytes=" << updated.size() << '\n';
        return 0;
    }
    const QString store = base + "/.local/share/flatpak/db/screencast";
    const QString backup = base + "/.local/share/flatpak/db/screencast.pre-automatic-hotplug-20261107.bak";
    if (!QFile::exists(backup) && !QFile::copy(store, backup)) {
        std::cerr << "BACKUP_FAILURE_OR_EXISTS\n"; return 8;
    }
    QFile::setPermissions(backup, QFile::ReadOwner | QFile::WriteOwner);
    auto write = [&](const QByteArray &data)->bool {
        QDBusArgument arg; arg.beginStructure();
        arg << QStringLiteral("KDE") << quint32(1) << QDBusVariant(QVariant(data));
        arg.endStructure();
        QDBusMessage request = QDBusMessage::createMethodCall(
            "org.freedesktop.impl.portal.PermissionStore",
            "/org/freedesktop/impl/portal/PermissionStore",
            "org.freedesktop.impl.portal.PermissionStore", "SetValue");
        request << QStringLiteral("screencast") << false << token
                << QVariant::fromValue(QDBusVariant(QVariant::fromValue(arg)));
        auto reply=bus.call(request,QDBus::Block,9000);
        return reply.type()!=QDBusMessage::ErrorMessage;
    };
    if (read()!=old) { std::cerr << "CONCURRENT_MODIFICATION_ABORT\n"; return 9; }
    const bool succeeded = write(updated);
    const QByteArray got = read();
    if (!succeeded || got!=updated) {
        if (got!=old && (!write(old)||read()!=old)) {
            std::cerr << "ROLLBACK_FAILED\n"; return 11;
        }
        std::cerr << "WRITE_NOT_VERIFIED_OR_ROLLED_BACK\n"; return 10;
    }
    std::cout << "KDE_HOTPLUG_GRANT_VERIFIED\n";
    return 0;
}

int main(int argc,char **argv) {
    QGuiApplication app(argc,argv);
    if (argc>1 && QString::fromLocal8Bit(argv[1])=="--check")
        return converge(app,false);
    if (argc>1 && QString::fromLocal8Bit(argv[1])=="--apply-once")
        return converge(app,true);
    if (argc!=2 || QString::fromLocal8Bit(argv[1])!="--watch") return 64;
    QTimer settle;
    settle.setSingleShot(true);
    settle.setInterval(1200);
    QObject::connect(&settle,&QTimer::timeout,&app,[&]() { converge(app,true); });
    auto connectScreen=[&](QScreen *screen) {
        QObject::connect(screen,&QScreen::geometryChanged,&app,[&](const QRect &) {
            settle.start();
        });
    };
    for (QScreen *screen: app.screens()) connectScreen(screen);
    QObject::connect(&app,&QGuiApplication::screenAdded,&app,[&](QScreen *s) {
        connectScreen(s);
        settle.start();
    });
    QObject::connect(&app,&QGuiApplication::screenRemoved,&app,[&](QScreen *) {
        settle.start();
    });
    QTimer::singleShot(0,&app,[&]() { converge(app,true); });
    return app.exec();
}